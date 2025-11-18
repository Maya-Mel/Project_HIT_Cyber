import mysql.connector
from dotenv import load_dotenv
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
        else:
            print("Failed to connect to the database")

    except mysql.connector.Error as err:
             print(f"Error: {err}")

