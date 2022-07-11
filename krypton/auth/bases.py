from abc import ABCMeta, abstractmethod
from typing import SupportsInt, ByteString

class user(metaclass=ABCMeta):
    @abstractmethod
    def delete(self):
        """The method name says it all."""
    @abstractmethod
    def login(self, pwd:str, mfaToken:SupportsInt=None):
        """The method name says it all."""
    @abstractmethod
    def restoreSession(self):
        """Resume a session after a new request"""
    @abstractmethod
    def logout(self):
        """The method name says it all."""
    @abstractmethod
    def enableMFA(self):
        """The method name says it all."""
    @abstractmethod
    def disableMFA(self):
        """The method name says it all."""
    @abstractmethod
    def createOTP(self):
        """The method name says it all."""
    @abstractmethod
    def saveNewUser(self):
        """The method name says it all."""
    @abstractmethod
    def getData(self, name: str) -> any:
        """The method name says it all."""
    @abstractmethod
    def setData(self, name: str, value: any) -> None:
        """The method name says it all."""
    @abstractmethod
    def deleteData(self, name:str) -> None:
        pass
    @abstractmethod
    def decryptWithUserKey(self, data:ByteString, sender:str, salt:bytes) -> bytes:
        """The method name says it all."""
    @abstractmethod
    def encryptWithUserKey(self, data:ByteString, otherUsers:list[str]) -> bytes:
        """The method name says it all."""
    @abstractmethod
    def generateNewKeys(self, pwd):
        """The method name says it all."""
    @abstractmethod
    def resetPWD(self):
        """The method name says it all."""
