import sqlite3

def show_data():
    conn = sqlite3.connect('users.db')  # Connect to the database
    cursor = conn.cursor()
    
    # Fetch all data from the 'users' table
    cursor.execute("SELECT * FROM users;")
    rows = cursor.fetchall()  # Retrieve all rows from the query result
    
    # Print the data
    print("Users table data:")
    for row in rows:
        print(row)
    
    conn.close()  # Close the connection

if __name__ == "__main__":
    show_data()
