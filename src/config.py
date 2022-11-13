# Config file for external binaries. Useful for Docker integration
# <name> : <list of arguments to launch the executable> (customizable)
# by default it is assumed the binaries are in your $PATH
EXTERNAL_BINARIES = {
    "apksigner": ["apksigner"],
    "adb": ["adb"],
}

# default backup file location for ADB backups
ADB_BACKUP_PATH = "/tmp/backup.tar"
