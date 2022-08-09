""" Utils to help code
"""
import datetime
from sqlalchemy import delete
from sqlalchemy.orm import scoped_session
from .. import DBschemas

def cleanUpSessions(session:scoped_session, userID:int = None):
    """Cleanup Expired Session or Remove all sessions for a user

    Arguments:
        session -- The database session to use

    Keyword Arguments:
        userID -- The ID for which to delete all sessions (even if not expired) (default: {None})
    """
    #If userID is provided all sessions linked to it will be deleted (even if they are not expired).
    now = datetime.datetime.now()
    if userID is not None:
        session.execute(
            delete(
                DBschemas.SessionKeys
            ).where(
                DBschemas.SessionKeys.Uid == userID
            ))
        session.flush()
    session.execute(
        delete(DBschemas.SessionKeys).where(DBschemas.SessionKeys.exp <= now))
    session.flush()
    session.commit()
