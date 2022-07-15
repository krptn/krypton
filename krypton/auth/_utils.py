import time
import datetime
from sqlalchemy import delete, select
from .. import configs, DBschemas

def cleanUpSessions(userID = None):
    """
    If userID is provided all sessions linked to it will be deleted (even if it is not expired). 
    """
    now = datetime.datetime.now()
    if userID is not None:
        configs.SQLDefaultCryptoDBpath.execute(delete(DBschemas.SessionKeys).where(DBschemas.SessionKeys.Uid == userID))
    configs.SQLDefaultCryptoDBpath.execute(delete(DBschemas.SessionKeys).where(DBschemas.SessionKeys.exp <= now))
    configs.SQLDefaultUserDBpath.flush()
    configs.SQLDefaultUserDBpath.commit()
