from termcolor import colored
from tabulate import tabulate
from .utils import CustomFormatter
import logging

class Analyzer():

    def __init__(self, parser):
        self.parser = parser
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Create stdout handler for logging to the console (logs all five levels)
        stdout_handler = logging.StreamHandler()
        stdout_handler.setFormatter(CustomFormatter())
        # Add handlers to the logger
        self.logger.addHandler(stdout_handler)

    def analyse_builtins_perms(self):
        self.logger.info("on analyse les perms bla bla")
        header = ["builtin Permissions"]
        table = []
        for perm in self.parser.builtinsPermission():
            if perm == 'android.permission.ACCESS_NETWORK_STATE':
                perm = colored(perm, "red")
            if perm == 'android.permission.GET_ACCOUNTS':
                perm = colored(perm, "yellow")
            table.append([perm])
        self.logger.info(tabulate(table, header, tablefmt="github"))
        # ajouter la logique
        self.logger.error(f"Found vulnerable perms : android.permission.ACCESS_NETWORK_STATE")



    def runAllTests(self):
        self.analyse_builtins_perms()