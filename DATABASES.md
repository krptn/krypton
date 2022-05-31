## Custom Databases 

# Microsoft SQL Server
You need to install [pyodbc](https://pypi.org/project/pyodbc/) and [Microsoft ODBC Driver for SQL Server](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver16)

The string that you need to pass to this extension should look like this:

```python
"mssql+pyodbc://user:password@server:port/dbname?driver=odbc driver e.g:ODBC+Driver+18+for+SQL+Server"
```

If you are only doing development you may add the following to prevent installing an SSL certificate:
```python 
&Encrypt=no
```  
To you windows authentication, please remove user:password from the string. 


# MySQL
Please install [pymysql](https://pypi.org/project/PyMySQL/). 
```python
"mysql+pymysql://user:password@host:port/database"
```

# SQLite
```python
"sqlite+pysqlite:///Path/example.db"
```

# Postgresql
Please install [psycopg2](https://pypi.org/project/psycopg2/).
```python
"postgresql+psycopg2://user:password@host:port/databse"
```
