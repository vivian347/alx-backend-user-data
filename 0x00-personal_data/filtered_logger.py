#!/usr/bin/env python3

import re
import logging
import os
from typing import List
import mysql.connector
from mysql.connector import connection

""" filtered logger
"""
PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """ returns log message to be obfuscated
    """
    return re.sub(r'(' + '|'.join(map(re.escape, fields)) +
                  r')=[^{}]+'.format(separator), r'\1=' + redaction, message)


def get_logger() -> logging.Logger:
    """ returns a logging.Logger obj
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    logger.propagate = False
    return logger


def get_db() -> connection.MySQLConnection:
    """connect to db with env vars"""
    db_username = os.getenv('PERSONAL_DATA_DB_USERNAME')
    db_pwd = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    db_host = os.getenv('PERSONAL_DATA_DB_HOST')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    connection = mysql.connector.connect(
        user=db_username,
        password=db_pwd,
        host=db_host,
        database=db_name,
    )

    return connection


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields=None):
        """constructor"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields or []

    def format(self, record: logging.LogRecord) -> str:
        """ filter vals in incoming log records using filter_datum
        """
        log_message = super().format(record)

        for field in self.fields:
            log_message = filter_datum([field],
                                       self.REDACTION, log_message,
                                       self.SEPARATOR)

        return log_message


def main() -> None:
    """
    Obtain a database connection using get_db
    and retrieve all rows in the users table and display each row
    """
    database = get_db()
    cur = database.cursor()

    cur.execute('SELECT * FROM users;')
    fetch_data = cur.fetchall()

    logger = get_logger()
    for row in fetch_data:
        fields = 'name={}; email={}; phone={}; ssn={}; password={}; ip={}; '\
            'last_login={}; user_agent={};'
        fields = fields.format(row[0], row[1], row[2], row[3],
                               row[4], row[5], row[6], row[7])
        logger.info(fields)

    cur.close()
    database.close()


if __name__ == "__main__":
    main()
