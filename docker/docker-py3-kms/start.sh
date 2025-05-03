#!/bin/bash
cd /home/py-kms

# Build base command
CMD="/usr/bin/python3 pykms_Server.py ${IP} ${PORT} -l ${LCID} -c ${CLIENT_COUNT} -a ${ACTIVATION_INTERVAL} -r ${RENEWAL_INTERVAL} -w ${HWID} -V ${LOGLEVEL} -F ${LOGFILE}"

# Add EPID if specified
if [ -n "${EPID}" ]; then
    CMD="${CMD} -e ${EPID}"
fi

# Add log size if specified
if [ -n "${LOGSIZE}" ]; then
    CMD="${CMD} -S ${LOGSIZE}"
fi

# Add web GUI if enabled
if [ "${WEB_GUI}" = "true" ]; then
    CMD="${CMD} --web-gui --web-port ${WEB_PORT}"
fi

# Add database configuration
if [ "${DB_TYPE}" != "sqlite" ]; then
    CMD="${CMD} --db-type ${DB_TYPE} --db-host ${DB_HOST} --db-name ${DB_NAME} --db-user ${DB_USER} --db-password ${DB_PASSWORD}"
else
    if [ "${SQLITE}" = "true" ]; then
        CMD="${CMD} -s ${PWD}/pykms_database.db"
    fi
fi

# Run the command
if [ "${SQLITE}" = "true" ] && [ -f "/home/sqlite_web/sqlite_web.py" ]; then
    # Start KMS server in background
    /bin/bash -c "${CMD} &"
    sleep 5
    # Start test client
    /usr/bin/python3 pykms_Client.py ${IP} ${PORT} -m Windows10 &
    # Start SQLite web interface
    /usr/bin/python3 /home/sqlite_web/sqlite_web.py -H ${IP} -x ${PWD}/pykms_database.db --read-only
else
    # Start KMS server in foreground
    exec ${CMD}
fi
