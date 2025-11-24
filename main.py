from DB_MANAGMENT import Establish_DB_Connection,printTopRows,AddUserToDB
from User_obj import User


def main():
    

    Current_Connection = Establish_DB_Connection()
    printTopRows(Current_Connection)

    Test_user = User("Elias", "LastName", "Elias@Mail.com","1234", "18-11-2003")
    AddUserToDB(Current_Connection,Test_user)



if __name__ == '__main__':
    main()