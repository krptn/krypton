import time
import datetime
from sqlalchemy import select
from .. import configs, DBschemas

def cleanUpSessions():
    time.sleep(15)
    now = datetime.datetime.now()
    stmt = select(DBschemas.SessionKeys).where(DBschemas.SessionKeys.exp <= now)
    result = configs.SQLDefaultUserDBpath.scalars(stmt)
    try:
        configs.SQLDefaultUserDBpath.delete(result)
    except:
        pass
    configs.SQLDefaultUserDBpath.commit()
