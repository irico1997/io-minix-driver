#include <minix/drivers.h>
#include <minix/driver.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <errno.h>
#include <unistd.h>
#include "secrets.h"

#define UNOWNED -1
#define TRUE 1
#define FALSE 0
#define O_WRONLY 2
#define O_RDONLY 4
#define O_RDWR 6

/*
 * Function prototypes for the secrets driver.
 */
FORWARD _PROTOTYPE( char * secrets_name,   (void) );
FORWARD _PROTOTYPE( int secrets_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secrets_close,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( struct device * secrets_prepare, (int device) );
FORWARD _PROTOTYPE( int secrets_transfer,  (int procnr, int opcode,
                                          u64_t position, iovec_t *iov,
                                          unsigned nr_req) );
FORWARD _PROTOTYPE( void secrets_geometry, (struct partition *entry) );
FORWARD _PROTOTYPE( int secrets_ioctl,     (struct driver *d, message *m) );
/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );

/* Entry points to the secrets driver. */
PRIVATE struct driver secrets_tab =
{
    secrets_name,
    secrets_open,
    secrets_close,
    secrets_ioctl,
    secrets_prepare,
    secrets_transfer,
    nop_cleanup,
    secrets_geometry,
    nop_alarm,
    nop_cancel,
    nop_select,
    nop_ioctl,
    do_nop,
};

/** Represents the /dev/secrets device. */
PRIVATE struct device secrets_device;

/** State variable to count the number of times the device has been opened. */
PRIVATE int open_counter;
PRIVATE int fd_counter;
PRIVATE char secret[SECRET_SIZE];
PRIVATE uid_t owner_uid;
PRIVATE int was_read;
PRIVATE int bytes_written;
PRIVATE int bytes_read;

PRIVATE int secrets_ioctl(d, m)
   struct driver *d;
   message *m;
{
   uid_t grantee;
   int res;
   if(m -> REQUEST != SSGRANT)
   {
      return ENOTTY;
   }
   res = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT, 0,
         (vir_bytes)&grantee, sizeof(grantee), D);
   if(res == -1)
   {
      printf("Unable to transfer control\n");
      return errno;
   }
   owner_uid = grantee;
   return OK; 
}

PRIVATE char * secrets_name(void)
{
    printf("secrets_name()\n");
    return "secrets";
}

PRIVATE int secrets_open(d, m)
    struct driver *d;
    message *m;
{
    struct ucred current_process;
    int access = m -> COUNT;
    int res;
    if(access == O_RDWR)
    {
      printf("Cannot open for R/W access\n");
      return EACCES;
    }
    res = getnucred(m->IO_ENDPT, &current_process);
    if(res == -1)
    {
       printf("Unable to get process credentials\n");
       return errno;
    }
    if(access == O_WRONLY)
    {
      if(owner_uid == UNOWNED)
      {
          owner_uid = current_process.uid;
          fd_counter ++;
          open_counter ++;
          printf("Writing to unowned secret, setting owner process to %d\n"
                "Current number of open FDs: %d\n", current_process.uid, fd_counter);
      }
      else if(owner_uid == current_process.uid)
      {
         printf("Cannot have multiple open write FDs\n");
         return ENOSPC;
      }
      else
      {
         printf("Current process does not own the secret\n");
         return EACCES;
      }
    }
    else if(access == O_RDONLY)
    {
      if(owner_uid == UNOWNED || owner_uid == current_process.uid)
      {
          owner_uid = current_process.uid;
          was_read = TRUE;
          fd_counter ++;
          open_counter ++;
          printf("Reading from secret, setting owner process to %d\n"
                "Current number of open FDs: %d\n", current_process.uid, fd_counter);
      }
      else
      {
         printf("Current process does not own the secret\n");
         return EACCES;
      }
    }
    else
    {
       printf("wadda hell... access: %d\n", access);
    }
    printf("secrets_open(). Called %d time(s).\n", open_counter);
    return res;
}

PRIVATE int secrets_close(d, m)
    struct driver *d;
    message *m;
{
    fd_counter --;
    printf("Closing secret, %d open file descriptors left\n", fd_counter);
    if(was_read && fd_counter == 0)
    {
       printf("Resetting secret\n");
       owner_uid = UNOWNED;
       was_read = FALSE;
       bytes_written = 0;
       bytes_read = 0;
       /* reset ownership */
    }
    printf("secrets_close()\n");
    return OK;
}

PRIVATE struct device * secrets_prepare(dev)
    int dev;
{
    secrets_device.dv_base.lo = 0;
    secrets_device.dv_base.hi = 0;
    secrets_device.dv_size.lo = strlen(SECRET_MESSAGE);
    secrets_device.dv_size.hi = 0;
    return &secrets_device;
}

PRIVATE int secrets_transfer(proc_nr, opcode, position, iov, nr_req)
    int proc_nr;
    int opcode;
    u64_t position;
    iovec_t *iov;
    unsigned nr_req;
{
    int bytes, res;
    struct ucred current;
    printf("secrets_transfer()\n");
    res = getnucred(proc_nr, &current);
    /*
    bytes = strlen(SECRET_MESSAGE) - position.lo < iov->iov_size ?
            strlen(SECRET_MESSAGE) - position.lo : iov->iov_size;
    */
    if(current.uid != owner_uid)
    {
       printf("Process does not own the secret, cannot read or write\n"\
              "Owner: %d Current: %d\n", owner_uid, current.uid);
       return EACCES;
    }

    if (iov-> iov_size <= 0)
    {
        return OK;
    }

    switch (opcode)
    {
        case DEV_GATHER_S:
           printf("Reading...\n");
           if(iov -> iov_size > bytes_written - bytes_read)
           {
              bytes = bytes_written - bytes_read;
           }
           res = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                               (vir_bytes) (secret[bytes_read]),
                                bytes, D);
           iov->iov_size -= bytes;
           bytes_read += bytes;
           printf("Read %d bytes out of %d.\n", bytes, iov -> iov_size);
           break;

        /*case DEV_GATHER_S:
            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (SECRET_MESSAGE + position.lo),
                                 bytes, D);
            iov->iov_size -= bytes;
            break;*/
        
        case DEV_SCATTER_S:
           printf("Writing...\n");
           if(iov -> iov_size + bytes_written > SECRET_SIZE)
           {
              printf("Cannot write outside the buffer size, %d\n"\
                    "Attempting to write %d bytes, already written %d\n",
                    SECRET_SIZE, iov -> iov_size, bytes_written);
              return ENOSPC;
           }
           res = sys_safecopyfrom(proc_nr, iov->iov_addr, 0,
                               (vir_bytes) (secret[bytes_written]),
                                bytes, D);
           bytes_written += iov -> iov_size;
           iov->iov_size -= iov -> iov_size;
           printf("Wrote %d bytes.\n", iov->iov_size);

           break;

        /*case DEV_SCATTER_S:
            ret = sys_safecopyfrom(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (SECRET_MESSAGE + position.lo),
                                 bytes, D);
            break;*/

        default:
            printf("Invalid request\n");
            return EINVAL;
    }
    return res;
}

PRIVATE void secrets_geometry(entry)
    struct partition *entry;
{
    printf("secrets_geometry()\n");
    entry->cylinders = 0;
    entry->heads     = 0;
    entry->sectors   = 0;
}

PRIVATE int sef_cb_lu_state_save(int state)
{
/* Save the state. */
    ds_publish_mem("open_counter", &open_counter, sizeof(open_counter), DSF_OVERWRITE);
    ds_publish_mem("secret", secret, sizeof(secret) * SECRET_SIZE, DSF_OVERWRITE);
    ds_publish_mem("owner", &owner_uid, sizeof(owner_uid), DSF_OVERWRITE);
    ds_publish_mem("fd_counter", &fd_counter, sizeof(fd_counter), DSF_OVERWRITE);
    ds_publish_mem("was_read", &was_read, sizeof(was_read), DSF_OVERWRITE);
    ds_publish_mem("bytes_written", &bytes_written, sizeof(bytes_written), DSF_OVERWRITE);
    ds_publish_mem("bytes_read", &bytes_read, sizeof(bytes_read), DSF_OVERWRITE);
    return OK;
}

PRIVATE int lu_state_restore() {
/* Restore the state. */
   /*
    int temp_ocounter;
    int temp_fdcounter;
    uid_t temp_owner;
    char temp_secret[SECRET_SIZE]; 
    int temp_read;
    int temp_bytes_written;
    int temp_bytes_read;
    ds_retrieve_mem("open_counter", (char *)(&temp_ocounter), sizeof(int));
    ds_retrieve_mem("fd_counter", (char *)(&temp_fdcounter), sizeof(int));
    ds_retrieve_mem("owner", (char *)(&temp_owner), sizeof(uid_t)); 
    ds_retrieve_mem("secret", (char *)(&temp_secret), sizeof(char) * SECRET_SIZE);
    ds_retrieve_mem("was_read", (char *)(&temp_read), sizeof(int));
    ds_retrieve_mem("bytes_written", (char *)(&temp_bytes_written), sizeof(int));
    ds_retrieve_mem("bytes_read", (char *)(&temp_bytes_read), sizeof(int));
    ds_delete_mem("open_counter");
    ds_delete_mem("fd_counter");
    ds_delete_mem("owner");
    ds_delete_mem("secret");
    ds_delete_mem("was_read");
    ds_delete_mem("bytes_written");
    ds_delete_mem("bytes_read");
    open_counter = temp_ocounter;
    fd_counter = temp_fdcounter;
    owner_uid = temp_owner; 
    secret = temp_secret;
    was_read = temp_read;
    bytes_written = temp_bytes_written;
    bytes_read = temp_bytes_read;
    */
    return OK;
}

PRIVATE void sef_local_startup()
{
    /*
     * Register init callbacks. Use the same function for all event types
     */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
     * Register live update callbacks.
     */
    /* - Agree to update immediately when LU is requested in a valid state. */
    sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready);
    /* - Support live update starting from any standard state. */
    sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard);
    /* - Register a custom routine to save the state. */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}

PRIVATE int sef_cb_init(int type, sef_init_info_t *info)
{
/* Initialize the secrets driver. */
    int do_announce_driver = TRUE;
    /* init globals */
    open_counter = 0;
    fd_counter = 0;
    bytes_read = 0;
    bytes_written = 0;
    was_read = FALSE;
    owner_uid = UNOWNED;
    switch(type) {
        case SEF_INIT_FRESH:
            printf("%s", SECRET_MESSAGE);
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("%sHey, I'm a new version!\n", SECRET_MESSAGE);
        break;

        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", SECRET_MESSAGE);
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        driver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

PUBLIC int main(int argc, char **argv)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    driver_task(&secrets_tab, DRIVER_STD);
    return OK;
}

