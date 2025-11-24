
from datetime import datetime

class User:
    def __init__(self, F_Name, L_Name, Mail, Password, DOFB):
        self.F_Name = F_Name
        self.L_Name = L_Name
        self.Mail = Mail
        self.Password = Password
        
        # Convert string date to datetime.date object
        if isinstance(DOFB, str):
            self.DOFB = datetime.strptime(DOFB, '%d-%m-%Y').date()
        else:
            self.DOFB = DOFB