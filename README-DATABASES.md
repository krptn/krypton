# Custom Databases

**Warning**: While all data that is saved to these databases are encrypted where necessary, please make sure that passwords for user accounts, user privileges, backup, etc. are properly configured in the database. Just because the data is encrypted, an unauthorized user can still delete it.

Internally, these strings are passed to SQLAlchemy to create an engine. To add extra connection parameters, please refer to SQLAlchemy's and/or your chosen database's SQL Driver documentation.

Please set these strings at:
```python
krypton.configs.SQLDefaultCryptoDBpath = # for DB used by Crypto Class
krypton.configs.SQLDefaultKeyDBpath =  # for DB used by Key Management System (you most likely don't need this)
krypton.configs.SQLDefaultUserDBpath = # for DB used by User Authentication System
```

## Microsoft SQL Server
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


## MySQL
Please install [mysqlclient](https://pypi.org/project/mysqlclient/).
```python
"mysql+mysqldb://user:password@host:port/database"
```

## SQLite
```python
"sqlite+pysqlite:///Path/example.db"
```

## Postgresql
Please install [psycopg2](https://pypi.org/project/psycopg2/).
```python
"postgresql+psycopg2://user:password@host:port/databse"
```
