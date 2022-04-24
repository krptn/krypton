from . import basic
from abc import ABCMeta, abstractmethod

class user(ABCMeta):
    _userName:str 
    @property
    @abstractmethod 
    def userName(self):
        pass
    @userName.setter
    @abstractmethod
    def userName(self, newName:str):
        pass
    @userName.getter
    @abstractmethod
    def userName(self):
        pass

    @abstractmethod
    def save(self):
        pass
    @abstractmethod
    def delete(self):
        pass

    @abstractmethod
    def login(self, pwd:str, mfaToken:int|None=None):
        pass
    @abstractmethod
    def logout(self):
        pass
