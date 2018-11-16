#include <minix/drivers.h>
#include <minix/driver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>
#include <errno.h>
#include "secrets.h"

#define UNOWNED -1
#define TRUE 1
#define FALSE 0
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
PRIVATE struct ucred owner;
PRIVATE int read;
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
   res = sys_safecopyfrom(m->IOENDPT, (vir_bytes)m->IO_GRANT, 0,
         (vir_bytes)&grantee, sizeof(grantee), D);
   if(res == -1)
   {
      return errno;
   }
   owner -> uid = grantee;
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
    int access = m -> DEV_OPEN -> COUNT;
    int res;
    uid_t grantee;
    if(access == RDWR)
    {
      return EACCES;
    }
    if(access == O_WRONLY)
    {
      if(owner -> uid == UNOWNED)
      {
          res = getnucred(m->SELF, &owner);
          if(res == -1)
          {
             return errno;
          }
          fd_counter ++;
          open_counter ++;
      }
      else
      {
         return ENOSPC;
      }
    }
    else if(access == O_RDONLY)
    {
      if(owner -> uid == UNOWNED)
      {
          res = getnucred(m->SELF, &owner);
          if(res == -1)
          {
             return errno;
          }
          read = TRUE;
          fd_counter ++;
          open_counter ++;
      }
    }
    printf("secrets_open(). Called %d time(s).\n", open_counter);
    return OK;
}

PRIVATE int secrets_close(d, m)
    struct driver *d;
    message *m;
{
    fd_counter --;
    if(read && fd_counter == 0)
    {
       owner -> uid = UNOWNED;
       read = FALSE;
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
    int bytes, ret;

    printf("secrets_transfer()\n");

    bytes = strlen(SECRET_MESSAGE) - position.lo < iov->iov_size ?
            strlen(SECRET_MESSAGE) - position.lo : iov->iov_size;

    if (bytes <= 0)
    {
        return OK;
    }
    switch (opcode)
    {
        case DEV_GATHER_S:
            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (SECRET_MESSAGE + position.lo),
                                 bytes, D);
            iov->iov_size -= bytes;
            break;

        case DEV_SCATTER_S:
            break;

        default:
            return EINVAL;
    }
    return ret;
}

PRIVATE void secrets_geometry(entry)
    struct partition *entry;
{
    printf("secrets_geometry()\n");
    entry->cylinders = 0;
    entry->heads     = 0;
    entry->sectors   = 0;
}

PRIVATE int sef_cb_lu_state_save(int state) {
/* Save the state. */
    ds_publish_mem("open_counter", &open_counter, sizeof(open_counter), DSF_OVERWRITE);
    ds_publish_mem("secret", secret, sizeof(secret) * SECRET_SIZE, DSF_OVERWRITE);
    ds_publish_mem("owner", &owner, sizeof(struct ucred), DSF_OVERWRITE);
    ds_publish_mem("fd_counter", &fd_counter, sizeof(fd_counter), DSF_OVERWRITE);
    ds_publish_mem("read", &read, sizeof(read), DSF_OVERWRITE);
    ds_publish_mem("bytes_written", &bytes_written, sizeof(bytes_written), DSF_OVERWRITE);
    ds_publish_mem("bytes_read", &bytes_read, sizeof(bytes_read), DSF_OVERWRITE);
    return OK;
}

PRIVATE int lu_state_restore() {
/* Restore the state. */
    int temp_ocounter;
    int temp_fdcounter;
    struct ucred temp_owner; /* check if this is right way */
    char temp_secret[SECRET_SIZE]; 
    int temp_read;
    int temp_bytes_written;
    int temp_bytes_read;
    ds_retrieve_mem("open_counter", &temp_ocounter, sizeof(temp_ocounter));
    ds_retrieve_mem("fd_counter", &temp_fd_counter, sizeof(temp_fd_counter));
    ds_retrieve_mem("owner", &temp_owner, sizeof(struct ucred)); /* hmmm */
    ds_retrieve_mem("secret", &temp_ocounter, sizeof(temp_ocounter));
    ds_retrieve_mem("read", &temp_ocounter, sizeof(temp_ocounter));
    ds_retrieve_mem("bytes_written", &temp_ocounter, sizeof(temp_ocounter));
    ds_retrieve_mem("bytes_read", &temp_ocounter, sizeof(temp_ocounter));
    ds_delete_mem("open_counter");
    ds_delete_mem("fd_counter");
    ds_delete_mem("owner");
    ds_delete_mem("secret");
    ds_delete_mem("read");
    ds_delete_mem("bytes_written");
    ds_delete_mem("bytes_read");
    open_counter = temp_ocounter;
    fd_counter = temp_fdcounter;
    owner = temp_owner; /* do i have to copy some dumbe way */
    secret = temp_secret;
    read = temp_read;
    bytes_written = temp_bytes_written;
    bytes_read = temp_bytes_read;
    /* init the rest */
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
    read = FALSE;
    owner -> uid = UNOWNED;
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

