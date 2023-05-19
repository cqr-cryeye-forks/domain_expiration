import json
import socket
import asyncio
import argparse
from datetime import datetime
from typing import NamedTuple, Dict, Union
from attr import attrs, attrib, Factory
import re

# noinspection PyPackageRequirements
import whois
# noinspection PyPackageRequirements
from whois.parser import PywhoisError, WhoisEntry

DEFAULT_DAYS_EXPIRATION = 60
NOT_EXIST_RESULT = {'domain': 'Not Exist', 'exist': False, 'expired': True}


class RunConfig(NamedTuple):
    target_domain: str
    output: str = 'result.json'
    write: bool = False
    json: bool = False
    quiet: bool = False


class ReadWriteDocuments(object):
    def __init__(self, result_file: str):
        self.result_file: str = result_file

    @classmethod
    def write_result_to_file(cls, result_file: str, result: str) -> None:
        """
        writes information to a file
        :param result_file: str file name to save result
        :param result: str string with result to save in file

        :return: None
        """
        obj = cls(result_file)
        with open(obj.result_file, 'w') as file:
            file.write(result)


class PrettyPrinter:
    def __init__(self, result: str):
        self.result = result

    @classmethod
    def run(cls, result: str) -> None:
        obj = cls(result)
        obj._print()

    def _print(self) -> None:
        print(self.result)


@attrs
class DomainChecker(object):
    config: RunConfig = attrib()
    _result: Union[str, Dict[str, str]] = attrib(default=Factory(dict))

    @classmethod
    async def from_config(cls, config: RunConfig) -> 'DomainChecker':
        """
        reads config variable and creates class
        :param config: RunConfig config for starting
        :return: Domain Checker
        """
        return cls(config=config)

    async def run(self) -> None:
        """
        starts async jobs from the main script file
        :return: None
        """
        if await self.is_registered():
            whois_info = whois.whois(self.config.target_domain)
            self.result = self.parse_info(whois_info)
        else:
            self.result = NOT_EXIST_RESULT

        self.create_string()

        if not self.config.quiet:
            PrettyPrinter.run(self.result)

        if self.config.write:
            ReadWriteDocuments.write_result_to_file(self.config.output, self.result)

    @staticmethod
    def parse_info(whois_info: WhoisEntry) -> Dict[str, str]:

        debug_check_info_from_whois = whois_info

        check_expired = whois_info.expiration_date[0] if type(whois_info.expiration_date) == list \
            else whois_info.expiration_date

        def process_values_rm_symbols(values, delimiters_pattern):
            if values:
                if not isinstance(values, list):
                    values = re.split(delimiters_pattern, str(values))
                    values = list(filter(None, values))
            return values

        def process_creation_dates(dates):
            if dates:
                if not isinstance(dates, list):
                    dates = [dates]
                dates = [date.isoformat() for date in dates]
            return dates

        def process_values(values):
            if values:
                if not isinstance(values, list):
                    values = [values]
                if "REDACTED FOR PRIVACY" in values:
                    values.remove("REDACTED FOR PRIVACY")
                    if len(values) == 0:
                        values = None
            return values

        return {

            'exist': True,

            'domain_name': process_values(whois_info.domain_name),
            "name_servers": process_values_rm_symbols(whois_info.name_servers, r"\s*\r?\n\s*"),
            'registrar': process_values_rm_symbols(whois_info.registrar, r"\s+d/b/a\s+"),

            'expiration_date': process_creation_dates(whois_info.expiration_date),
            'expired': check_expired < datetime.now(),
            'expire_soon': (check_expired - datetime.now()).days <= DEFAULT_DAYS_EXPIRATION,
            'creation_date': process_creation_dates(whois_info.creation_date),
            'updated_dates': process_creation_dates(whois_info.updated_date),

            'emails': process_values(whois_info.emails),

            'address': process_values(whois_info.address),
            'city': process_values(whois_info.city),
            'state': process_values(whois_info.state),
            'country': process_values(whois_info.country),
            'registrant_postal_code': process_values(whois_info.registrant_postal_code),
        }

    def create_string(self):
        if self.config.json:
            self.result = json.dumps(self.result)
        else:
            self.result = ''.join(f'{key}: {value}\n' for key, value in self.result.items())

    async def is_registered(self) -> bool:
        """
        Check if domain valid and registered
        :return: bool
        """
        try:
            w = whois.whois(self.config.target_domain)
        except (PywhoisError, socket.herror):
            return False
        else:
            return bool(w.domain_name)

    @property
    def result(self) -> Union[str, Dict[str, str]]:
        return self._result

    @result.setter
    def result(self, result: Union[str, Dict[str, str]]) -> None:
        self._result = result


def define_config_from_cmd(parsed_args: 'argparse.Namespace') -> RunConfig:
    """
    parsing config from args
    :param parsed_args: argparse.Namespace
    :return: RunConfig
    """
    return RunConfig(
        target_domain=parsed_args.target,
        output=parsed_args.output,
        write=parsed_args.write,
        json=parsed_args.json,
        quiet=parsed_args.quiet,
    )


def cli() -> argparse.Namespace:
    """
    here we define args to run the script with
    :return: argparse.Namespace
    """
    parser = argparse.ArgumentParser(description='Domain Expiration')

    # Add the arguments to the parser
    parser.add_argument('-t', '--target', required=True, help='target url', type=str)

    parser.add_argument(
        '-o', '--output', required=False, help='file to save result in', default='result.json', type=str)
    parser.add_argument('-w', '--write', required=False, dest='write', action='store_true', default=False,
                        help='write results to file')
    parser.add_argument('-j', '--json', required=False, dest='json', action='store_true', default=False,
                        help='json output')

    parser.add_argument(
        '-q', '--quiet', required=False, help='quiet mod, only save to file', action='store_true', default=False)

    return parser.parse_args()


async def main() -> None:
    parsed_args = cli()
    run_config = define_config_from_cmd(parsed_args=parsed_args)
    domain_checker = await DomainChecker.from_config(config=run_config)
    await domain_checker.run()


if __name__ == '__main__':
    asyncio.run(main())
