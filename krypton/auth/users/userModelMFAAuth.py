from .bases import userExistRequired, user

class MFAUser(user):
    @userExistRequired
    def resetPWD(self):
        """The method name says it all."""

    @userExistRequired
    def enableMFA(self):
        """The method name says it all."""

    @userExistRequired
    def disableMFA(self):
        """The method name says it all."""

    @userExistRequired
    def createOTP(self):
        """The method name says it all."""
