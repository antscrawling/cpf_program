from cpf_config_loader_v11 import CPFConfig
from cpf_program_v11 import CPFAccount
from tqdm import tqdm  # For the progress bar
from cpf_date_generator_v3 import DateGenerator
import os
import sqlite3
import json
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta

# Dynamically determine the src directory
SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
DATABASE_NAME = os.path.join(SRC_DIR, 'cpf_simulation.db')  # Full path to the database file
DATE_KEYS = ['startdate', 'enddate', 'birthdate']
DATE_FORMAT = "%Y-%m-%d"

# Load the configuration file
#config_loader = ConfigLoader(CONFIG_FILENAME)

def create_connection():
    """Creates a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        print(sqlite3.version)
    except sqlite3.Error as e:
        print(e)
    return conn

def create_table(conn):
    """Creates a table to store CPF simulation data."""
    try:
        sql = """
        CREATE TABLE IF NOT EXISTS cpf_data (
            date_key TEXT PRIMARY KEY,
            dbreference INTEGER,
            age INTEGER,
            oa_balance REAL,
            sa_balance REAL,
            ma_balance REAL,
            ra_balance REAL,
            loan_balance REAL,
            excess_balance REAL,
            cpf_payout REAL,
            message TEXT
        );
        """
        cur = conn.cursor()
        cur.execute(sql)
    except sqlite3.Error as e:
        print(e)

def loan_computation_first_three_years(cpf):
    # Corrected implementation for loan_payments
    #loan_payments = cpf.config.getdata('loanpayments', {})
    payment_key = 'year12' if cpf.age < 24 else 'year3'
    float(getattr(cpf.config, f'loanpayments{payment_key}', 0.0)) 

def compute_age(startdate : datetime.date, birthdate : datetime.date) -> int:
    """
    Compute the age based on the start date and birth date.
    The age increments by 1 every July 6.
    """
    # Calculate the base age
    base_age = relativedelta(startdate, birthdate).years
    #if startdate.month >= birthdate.month:
    #    base_age += 1
    return  base_age
                
                
def main():
    # Step 1: Load the configuration
    config_loader = CPFConfig(CONFIG_FILENAME)
    startdate = config_loader.startdate
    enddate = config_loader.enddate
    birthdate = config_loader.birthdate
    payouttype = config_loader.payouttype
    if config_loader.pledgeyourhdbat55.lower() == 'no':
        retirement_amount = getattr(config_loader, f'retirementsums{payouttype}amount', 0) 
    else: 
        retirement_amount = config_loader.retirementsumsfrsamount /2
    
    # Validate that the dates are loaded correctly
    if not all([startdate, enddate, birthdate]):
        raise ValueError("Missing required date values in the configuration file. Please check 'startdate', 'enddate', and 'birthdate'.")

    # Step 2: Generate the date dictionary
    dategen = DateGenerator(start_date=startdate, end_date=enddate, birth_date=birthdate)
    date_dict = dategen.generate_date_dict()
    dategen.save_file(dategen.date_list, format='csv')  # Step 3 Save the date_dict to file after generation
  
    if not date_dict:
        print("Error: date_dict is empty. Loop will not run.")
        return  # Exit if empty

    is_initial = True
    is_display_special_july = False
    # Step 4: Calculate CPF per month using CPFAccount
    with CPFAccount(config_loader) as cpf:
        # Step 5  Set the initial values
        cpf.startdate = cpf.convert_date_strings(key='startdate', date_str=startdate)
        cpf.enddate = cpf.convert_date_strings(key='enddate', date_str=enddate)
        cpf.birthdate = cpf.convert_date_strings(key='birthdate', date_str=birthdate)
        cpf.current_date =  cpf.startdate
        cpf.age = compute_age(cpf.startdate, cpf.birthdate)
        cpf.date_key = cpf.current_date.strftime('%Y-%m')
        
       
     
        # Step 6 print headers
        # Violet color ANSI escape code
        violet = "\033[35m"
        reset = "\033[0m"  # Reset color to default

        print(f"{violet}{'Simulation of CPF Data':^150}{reset}")
        print(f"{violet}====================================={reset}")
        print(f"{violet}== Start Date: {cpf.startdate}{reset}")
        print(f"{violet}== End Date: {cpf.enddate}{reset}")
        print(f"{violet}== Birth Date: {cpf.birthdate}{reset}")
        print(f"{violet}== Age: {cpf.age}{reset}")
        print(f"{violet}== Retirement Amount: {retirement_amount:>18,.2f}{reset}")
        print(f"{violet}== OA Balance Amount: {config_loader.oabalance:>18,.2f}{reset}")
        print(f"{violet}== SA Balance Amount: {config_loader.sabalance:>18,.2f}{reset}")
        print(f"{violet}== MA Balance Amount: {config_loader.mabalance:>18,.2f}{reset}")
        print(f"{violet}== Loan Balance Amount: {config_loader.loanbalance:>16,.2f}{reset}")
        print(f"{violet}======================================{reset}")
        print(f"{violet}{'-' * 150}{reset}")
        # Step 7 print the headers
        print(f"{'Month and Year':<15}{'Age':<5}{'OA Balance':<15}{'SA Balance':<15}{'MA Balance':<15}{'RA Balance':<15}{'Loan Amount':<12}{'Excess Cash':<12}{'CPF Payout':<12}")
        print("-" * 150)

        # Step 8  determine if inital balance is needed.
        if is_initial:
            print("Loading initial balances from config...")
            # Use property setters to ensure logging                                                                                                            
            # Step 9 set the initial balances
           
            initoa_balance = float(config_loader.oabalance)
            initsa_balance = float(config_loader.sabalance)
            initma_balance = float(config_loader.mabalance)
            initra_balance = float(config_loader.rabalance)
            initexcess_balance = float(config_loader.excessbalance)
            initloan_balance = float(config_loader.loanbalance)
            #Step 10 record the initial balances
            for account, new_balance in zip(['oa', 'sa', 'ma', 'ra', 'excess', 'loan'], [initoa_balance, initsa_balance, initma_balance, initra_balance, initexcess_balance, initloan_balance]):
                cpf.record_inflow(account=account, amount=new_balance, message=f"Initial Balance of {account}")
            is_initial = False
            
       #  Step 11 get loan payments from config
        loan_paymenty1 = float(config_loader.loanpaymentsyear12)      
        loan_paymenty3 = float(config_loader.loanpaymentsyear3)
        loan_paymenty4 = float(config_loader.loanpaymentsyear4beyond)     
     
       
                                                                                  
        year = 1  # this is for the loan payments
      
        with create_connection() as conn:
            create_table(conn)
            ###################################################################################
            # LOOP STARTS HERE
            ###################################################################################
           
            for date_key, date_info in tqdm(date_dict.items(), desc="Processing CPF Data", unit="month", colour="blue"):                                                               
                # Step 12: Update the current date and age
                cpf.dbreference = cpf.add_db_reference() #this is a unique reference for logging.
                cpf.date_key = date_key
                cpf.current_date = date_dict[date_key]['period_end'] #just get the values already generated.
                cpf.age = compute_age(cpf.current_date, cpf.birthdate)
              
                # Step 13 loan payments
                
                if year == 1 and cpf._loan_balance > 0:
                    cpf.record_outflow(account='oa',   amount=loan_paymenty1, message=f"Loan payment from OA Account at year 1 age {cpf.age}")
                    cpf.record_outflow(account='loan', amount=loan_paymenty1, message=f"Loan payment from OA Account at year 1 age {cpf.age}")
                elif year == 2 and cpf._loan_balance > 0:
                    cpf.record_outflow(account='oa',   amount=loan_paymenty1, message=f"Loan payment from OA Account at year 2 age {cpf.age}")
                    cpf.record_outflow(account='loan', amount=loan_paymenty1, message=f"Loan payment from OA Account at year 2 age {cpf.age}")
                elif year == 3 and cpf._loan_balance > 0:
                    cpf.record_outflow(account='oa',   amount=loan_paymenty3, message=f"Loan payment from OA Account at year 3 age {cpf.age}")
                    cpf.record_outflow(account='loan', amount=loan_paymenty3, message=f"Loan payment from OA Account at year 3 age {cpf.age}")
                elif year >= 4 and cpf._loan_balance > 0:
                   
                    if cpf._loan_balance > 0:
                        loan_payment = min(loan_paymenty4, cpf._loan_balance)
                        cpf.record_outflow(account='oa', amount=loan_payment, message=f"Loan payment from OA Account at year 4, age {cpf.age}")
                        cpf.record_outflow(account='loan', amount=loan_payment, message=f"Loan payment from OA Account at year 4, age {cpf.age}")
                    elif cpf._loan_balance < 3000:
                        loan_payment = min(loan_paymenty4, cpf._loan_balance)
                    else:
                        cpf.loan_balance = 0.0
                year += 1
                # Step 14 Allocation of CPF Salaries to each account          
                if cpf.age < 55:    
                    cpf.record_inflow(account='oa', amount=config_loader.allocationbelow55oaamount.__round__(2), message=f"Allocation for OA at age {cpf.age}")
                    cpf.record_inflow(account='sa', amount=config_loader.allocationbelow55saamount.__round__(2), message=f"Allocation for SA at age {cpf.age}")
                    cpf.record_inflow(account='ma', amount=config_loader.allocationbelow55maamount.__round__(2), message=f"Allocation for MA at age {cpf.age}")
                # Step 15 at the age of 55, SA Balance is closed and transferred to RA.  OA Balance is also transferred to RA.
                elif cpf.age == 55 and cpf.current_date.month == cpf.birthdate.month :
                          
                    cpf.record_inflow(account='oa', amount=config_loader.allocationbelow55oaamount.__round__(2), message=f"Allocation for OA at age {cpf.age}")
                    cpf.record_inflow(account='sa', amount=config_loader.allocationbelow55saamount.__round__(2), message=f"Allocation for SA at age {cpf.age}")
                    cpf.record_inflow(account='ma', amount=config_loader.allocationbelow55maamount.__round__(2), message=f"Allocation for MA at age {cpf.age}")
                else:  # Step 16 allocation for 55 and above
                    if 55 <= cpf.age < 60  and cpf.current_date.month >=8 :                              
                        age_key = '56to60'
                    if 60 <= cpf.age < 65:
                        age_key = '61to65'
                    if 65 <= cpf.age < 70:
                        age_key = '66to70'
                    else:
                        age_key = 'above70'

                    # Get the allocation amounts from the config
                    for account in ['oa', 'ma', 'ra']:
                        allocation_amount = getattr(config_loader,f'allocationabove55{account}{age_key}amount',0 ) # dicct.get('allocation_above_55',{}).get(account,{}).get(age_key,{}).get('amount', 0.0))
                        cpf.record_inflow(account=account, amount=allocation_amount.__round__(2), message=f"Allocation for {account} at age {cpf.age}")
                                                         
                # Step 17 Apply interest at the end of the year
                if cpf.current_date.month == 12:                   
                    account_balance = 0.0
                    oa_interest = 0.0
                    sa_interest = 0.0
                    ma_interest = 0.0
                    ra_interest = 0.0
                    oa_extra_interest = 0.0
                    sa_extra_interest = 0.0
                    ma_extra_interest = 0.0
                    ra_extra_interest = 0.0                

                    for account in ['oa', 'sa', 'ma', 'ra']:
                        cpf.message = f"Applying interest for {account} at age {cpf.age}"
                        account_balance = getattr(cpf, f'_{account}_balance', 0.0)
                        if account_balance > 0:
                            if account == 'oa':
                                oa_interest = round(cpf.calculate_interest_on_cpf(account=account,  amount=account_balance),2)
                            elif account == 'sa':
                                sa_interest = round(cpf.calculate_interest_on_cpf(account=account,  amount=account_balance),2)
                            elif account == 'ma':
                                ma_interest = cpf.calculate_interest_on_cpf(account=account,  amount=account_balance).__round__(2)
                            elif account == 'ra':
                                ra_interest = cpf.calculate_interest_on_cpf(account=account,  amount=account_balance).__round__(2)
                    # Step 18  Record the interest inflow                                                       
                    oa_extra_interest, sa_extra_interest, ma_extra_interest, ra_extra_interest = cpf.calculate_extra_interest()
                    cpf.record_inflow(account='oa', amount=oa_interest, message=f"Interest for {account} at age {cpf.age}")
                    cpf.record_inflow(account='sa', amount=sa_interest, message=f"Interest for {account} at age {cpf.age}")
                    cpf.record_inflow(account='ma', amount=ma_interest, message=f"Interest for {account} at age {cpf.age}")
                    cpf.record_inflow(account='ra', amount=ra_interest, message=f"Interest for {account} at age {cpf.age}")
                    cpf.record_inflow(account='oa', amount=oa_extra_interest.__round__(2), message=f"Extra Interest for {account} at age {cpf.age}")
                    cpf.record_inflow(account='sa', amount=sa_extra_interest.__round__(2), message=f"Extra Interest for {account} at age {cpf.age}")
                    cpf.record_inflow(account='ma', amount=ma_extra_interest.__round__(2), message=f"Extra Interest for {account} at age {cpf.age}")
                    cpf.record_inflow(account='ra', amount=ra_extra_interest.__round__(2), message=f"Extra Interest for {account} at age {cpf.age}")                                                                                                

                # Step 19 CPF payout calculation
                
                if hasattr(cpf, 'calculate_cpf_payout'):
                    cpf.payout = cpf.calculate_cpf_payout(payouttype) 
                    if isinstance(cpf.payout, (int, float)):
                        cpf.payout = max(min(cpf.payout, cpf._ra_balance),0.00)
                        setattr(cpf, 'payout', cpf.payout)
                        if cpf._ra_balance > 0:
                            cpf.record_outflow(account='ra',   amount=cpf.payout, message=f"CPF payout at age {cpf.age}")
                            cpf.record_inflow(account='excess',amount=cpf.payout, message=f"CPF payout at age {cpf.age}")
                        else:
                            cpf.payout = 0.0
                       
                if cpf._ra_balance == 0.0 and cpf.age > 55:
                    print(f"Stopping simulation at age {cpf.age} as RA balance is zero.")
                    break


                # Step 20 Display balances including July 2029
                cpf.date_key = date_key
                oa_bal = getattr(cpf, '_oa_balance', 0.0).__round__(2)
                sa_bal = getattr(cpf, '_sa_balance', 0.0).__round__(2)
                ma_bal = getattr(cpf, '_ma_balance', 0.0).__round__(2)
                ra_bal = getattr(cpf, '_ra_balance', 0.0).__round__(2)
                loan_bal = getattr(cpf, '_loan_balance', 0.0).__round__(2)
                excess_bal = getattr(cpf, '_excess_balance', 0.0).__round__(2)
                payout = getattr(cpf, 'payout', 0.0).__round__(2)
                print(f"{date_key:<15}{cpf.age:<5}"
                      f"{float(oa_bal):<15,.2f}{float(sa_bal):<15,.2f}"
                      f"{float(ma_bal):<15,.2f}{float(ra_bal):<15,.2f}"
                      f"{float(loan_bal):<12,.2f}{float(excess_bal):<12,.2f}"
                      f"{float(cpf.payout):<12,.2f}")
                
                
                
                # Step 21 Special case for age 55 and month 7
                if cpf.age == 55 and cpf.current_date.month == cpf.birthdate.month :
                    is_display_special_july = True
                    orig_oa_bal = oa_bal
                    orig_sa_bal = sa_bal
                    orig_ma_bal = ma_bal
                    orig_loan_bal = loan_bal
                    orig_cpf_payout = payout
                
                 # this is to print a special information for birthday month at age 55                         
                if is_display_special_july:    
                    # Step 22 Special printing for age 55 and month 7
                                        
                    if not (config_loader.ownhdb.lower() == 'yes' and  config_loader.pledgeyourhdbat55.lower() == 'yes'):
                        retirement_amount = getattr(config_loader, f'retirementsums{payouttype}amount', 0.0).__round__(2)
                        display_date_key = f"{date_key}-cpf"
                        display_oa_bal = -orig_oa_bal
                        display_sa_bal = -orig_sa_bal
                        display_ma_bal = orig_ma_bal
                        display_loan_bal = -orig_loan_bal if loan_bal > 0 else 0.0             
                        display_ra_bal =  retirement_amount
                        display_excess_bal = (orig_oa_bal + orig_sa_bal - orig_loan_bal - retirement_amount)
                        display_cpf_payout = orig_cpf_payout
                        ##   
                    else: # meaning you pledged your hdb house at age 55. RA Amount is FRS / 2 
                        retirement_amount = (config_loader.retirementsumsfrsamount / 2 ).__round__(2)
                        display_date_key = f"{date_key}-cpf"
                        display_oa_bal = -orig_oa_bal
                        display_sa_bal = -orig_sa_bal
                        display_ma_bal = orig_ma_bal
                        display_loan_bal = -orig_loan_bal if loan_bal > 0 else 0.0             
                        display_ra_bal =  retirement_amount
                        display_excess_bal = (orig_oa_bal + orig_sa_bal - orig_loan_bal - retirement_amount)
                        display_cpf_payout = orig_cpf_payout
                                                       
                    print(f"{display_date_key:<15}{cpf.age:<4}"
                          f"{float(display_oa_bal):<15,.2f}{display_sa_bal:<15,.2f}"
                          f"={float(display_ma_bal):<14,.2f}+{float(display_ra_bal):<14,.2f}"
                          f"{float(display_loan_bal):<13,.2f}{float(display_excess_bal):<12,.2f}"
                          f"{float(display_cpf_payout):<12,.2f}")

                    
                      
                    # Step 23 Record the special case in the database
                    cpf.record_inflow(account= 'oa',  amount= display_oa_bal,  message= f"transfer_cpf_age={cpf.age}")
                    cpf.record_inflow(account= 'sa',  amount= display_sa_bal,  message= f"transfer_cpf_age={cpf.age}")
                    cpf.record_inflow(account= 'loan',amount= display_loan_bal,message= f"transfer_cpf_age={cpf.age}")
                    cpf.record_inflow(account= 'ra',  amount= display_ra_bal,  message= f"transfer_cpf_age={cpf.age}")
                    cpf.record_inflow(account= 'excess',amount= display_excess_bal,message= f"transfer_cpf_age={cpf.age}")
                    
                    
                    is_display_special_july = False   
                    
                # Step 24 Insert data into the database for every iteration
                if cpf.age == 55 :
                    cpf.message = f"Age 55 - Special case for CPF payout"
                elif cpf._ra_balance == 0.0 and cpf.age >= 55:
                    cpf.message = f"Age {cpf.age} - RA balance is zero"
                elif  cpf.age == 67:
                    cpf.message = f"Age {cpf.age} - CPF payout"
                elif cpf.current_date.month == 12:
                    cpf.message = f"End of year {cpf.age} - CPF Interest"
                else :
                    cpf.message = f"Age {cpf.age} - Regular CPF calculation" 
                if not is_display_special_july:
                    cpf.insert_data(conn, str(date_key),int(cpf.dbreference) ,int(cpf.age), float(oa_bal), float(sa_bal), float(ma_bal), float(ra_bal), float(loan_bal), float(excess_bal), float(payout),str(cpf.message))
                    

if __name__ == "__main__":
    # Call the main function 
    main()















































































