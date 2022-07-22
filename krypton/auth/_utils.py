""" Utils to help code
"""
import datetime
from sqlalchemy import delete
from .. import configs, DBschemas

def cleanUpSessions(userID = None):
    """cleanUpSessions Delete expired Session Keys

    Keyword Arguments:

        userID -- Delete all tokens from this ID even if not expired (default: {None})
    """
    #If userID is provided all sessions linked to it will be deleted (even if it is not expired).

    now = datetime.datetime.now()
    if userID is not None:
        configs.SQLDefaultUserDBpath.execute(
            delete(
                DBschemas.SessionKeys
            ).where(
                DBschemas.SessionKeys.Uid == userID
            ))
    configs.SQLDefaultUserDBpath.execute(
        delete(DBschemas.SessionKeys).where(DBschemas.SessionKeys.exp <= now))
    configs.SQLDefaultUserDBpath.flush()
    configs.SQLDefaultUserDBpath.commit()
