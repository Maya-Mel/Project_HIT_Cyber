import mysql.connector
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_USER_ADMIN = os.getenv("MYSQL_USER_ADMIN")
MYSQL_DB_NAME = os.getenv("MYSQL_DB_NAME")




def Establish_DB_Connection():
    try:
        MYSQL_CONNECTION = mysql.connector.connect(
            host="localhost",
            user= MYSQL_USER_ADMIN,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB_NAME
        )

        if MYSQL_CONNECTION.is_connected():
           print("Connected to the database")
           return MYSQL_CONNECTION
        else:
            print("Failed to connect to the database")

    except mysql.connector.Error as err:
             print(f"Error: {err}")

def printTopRows(MYSQL_CONNECTION):
     try:
          MY_Current_Sesion = MYSQL_CONNECTION.cursor()
          query = f"SELECT * FROM comunication_ltd.users"

          MY_Current_Sesion.execute(query)
          print(MY_Current_Sesion.fetchall())

     except mysql.connector.Error as err:
             print(f"Error: {err}")


def AddUserToDB(MYSQL_CONNECTION, user):
     try:
          MY_Current_Sesion = MYSQL_CONNECTION.cursor()

          if isinstance(user.DOFB, str):
               date_obj = datetime.strptime(user.DOFB, '%d/%m/%Y').date()  
          else:
               date_obj = user.DOFB

          query = "INSERT INTO comunication_ltd.users (first_name,last_name,email,password,date_of_birth) VALUES (%s, %s, %s, %s, %s)"

          MY_Current_Sesion.execute(query, (user.F_Name, user.L_Name, user.Mail, user.Password, date_obj))
          MYSQL_CONNECTION.commit()
          print(f"User added successfully. Rows affected: {MY_Current_Sesion.rowcount}")


     except mysql.connector.Error as err:
             print(f"Error: {err}")

     

     