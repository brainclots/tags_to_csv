''' Read in taglist data to a dictionary

Author:
            ___  ____ _ ____ _  _    _  _ _    ____ ___ ___
            |__] |__/ | |__| |\ |    |_/  |    |  |  |    /
            |__] |  \ | |  | | \|    | \_ |___ |__|  |   /__

            Tripwire MSE

Version: 1.0
Date: January 2020

'''
import click
import subprocess
from  customer_dict import customer_dict
from pathlib import Path, PureWindowsPath
import ctypes
import time
from datetime import date

tecmdr_windir = PureWindowsPath('C:/Program Files/Tripwire/tw-tecommander')
tecmdr = tecmdr_windir / 'bin' / 'tecommander.cmd'

@click.command()
@click.option('-c', '--customer', help='Customer name (in quotes if contains spaces), or "all"')
@click.option('-u', '--username', envvar='USERNAME', help='Specify username (if different than your login id)')
@click.option('-g', '--node_group', help='Node Group name (in quotes if contains spaces)')

def main(customer, username, node_group):
    '''
    This will extract a list of all nodes in the supplied node group and write them to a CSV file.
    '''
    start = time.time()
    customer, cust_values, node_group = confirm(customer, node_group)
    cmdr_output = run_tecmdr(customer, cust_values['auth_file'], node_group)
    p = Path(username) / customer
    p.mkdir(exist_ok=True, parents=True)
    outfile = p / f'{customer}_taglist.csv'
    click.echo(f'Sorting and writing results to {outfile}.')

    tagdict = {}
    currentkey = ''
    value=[]
    for item in cmdr_output:
        if item.startswith('Node:'):
            currentkey = item[5:]
            tagdict[currentkey] = value
        elif item != '':
            value.append(item)
        elif item == '': # Hit a blank line, start next key in dictionary
            if not currentkey == '':
                tagdict.update(currentkey = value)
            value =[]

    if tagdict['currentkey']:
        del tagdict['currentkey']
    currentdate = date.today()
    with open(outfile, 'w') as f:
        f.write(f'Tags for all nodes at {customer} in SmartNode group \"{node_group}\" as of {currentdate.strftime("%m-%d-%y")}\n')
        for key in sorted(tagdict.keys(), key=str.casefold):
            alltags = ''
            for val in sorted(tagdict[key]):
                alltags = f'{alltags},{val}'
            f.write(f'{key}{alltags}\n')
    end = time.time()
    elapsed = str(round(end - start, 2))
    print(f'Script run took {elapsed} seconds.')


def confirm(customer, node_group):
    if customer:
        cust_values = get_from_dict(customer)
    else:
        customer_menu = list(customer_dict.keys())
        customer_menu.sort()
        click.echo('Please select the number of the customer:')
        for i,c in enumerate(customer_menu, 1):
            click.echo(f'\t{i:>4}. {c}')
        selection = input('Your choice: ')
        if int(selection) in range(1, len(customer_menu) + 1):
            customer = customer_menu[int(selection) - 1]
        else:
            click.echo(f'Invalid selection! {selection} is not in the list!')
            exit()
        cust_values = get_from_dict(customer)

    if not node_group:
        node_group = click.prompt('Node Group', default='Monitoring Enabled').strip('"')

    return customer, cust_values, node_group


def get_from_dict(customer):
    if customer in customer_dict.keys():
        cust_values = customer_dict[customer]
        return(cust_values)
    else:
        print(f'Error: Customer "{customer}" does not exist!' )
        exit()


def run_tecmdr(customer, auth_file, node_group):
        cmd_list = [f'"{str(tecmdr)}"', 'avlistassettags',
                    '-w', f'"{node_group}"',
                    '-M', auth_file,
                    '-q', '-Q']
        try:
            print(f'\nGetting list of tags for nodes in "{node_group}" for {customer}...')
            print('(Be patient, TECommander can take a bit of time to get the data you request.)')
            output = subprocess.check_output(' '.join(cmd_list), shell=True)
        except subprocess.CalledProcessError as err:
            print('Error: ', err.returncode, err.output)

        try:
            output
        except NameError:
            print('\nNo output obtained from TECommander. Troubleshoot accordingly.')
            exit(1)
        else:
            content = output.decode('utf-8').splitlines()
        return content


if __name__ == '__main__':
    # Check to see if we are running as an administrator
    IsAdmin = ctypes.windll.shell32.IsUserAnAdmin()
    if IsAdmin == 0:
        click.echo('Please execute the script from an *Administrator* (elevated) command prompt')
        exit(1)

    main()
