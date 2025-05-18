import pandas as pd
import os

SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
LOGFILE = os.path.join(SRC_DIR, 'cpf_log_file.csv')  # Full path to the log file
CPFREPORT = os.path.join(SRC_DIR, 'cpf_report.csv')  # Full path to the report file
OUTPUT_MISMATCHES = os.path.join(SRC_DIR, 'cpf_mismatches.csv')  # Output file for mismatches
OUTPUT_BALANCES = os.path.join(SRC_DIR, 'cpf_final_balances.csv')  # Output file for final balances

def analyze_cpf_files(log_file_path, report_file_path, mismatches_file_path, balances_file_path):
    # Load the CSV files into pandas dataframes
    log_df = pd.read_csv(log_file_path)
    report_df = pd.read_csv(report_file_path)

    # Extract relevant fields from cpf_log_file.csv
    log_df = log_df[['transaction_reference', 'amount', 'account', 'type']]
    log_df = log_df[log_df['account'].isin(['oa', 'ma', 'sa', 'ra', 'loan', 'excess'])]  # Filter valid accounts
    log_df = log_df[log_df['type'].isin(['inflow', 'outflow'])]  # Filter valid types

    # Extract relevant fields from cpf_report.csv
    report_df = report_df[['REF', 'ACCOUNT', 'INFLOW', 'OUTFLOW']]
    report_df = report_df[report_df['ACCOUNT'].isin(['oa', 'ma', 'sa', 'ra', 'loan', 'excess'])]  # Filter valid accounts

    # Melt the report_df to combine INFLOW and OUTFLOW into a single column
    report_df = report_df.melt(
        id_vars=['REF', 'ACCOUNT'],
        value_vars=['INFLOW', 'OUTFLOW'],
        var_name='type',
        value_name='amount'
    )
    report_df['type'] = report_df['type'].str.lower()  # Convert type to lowercase for consistency
    report_df = report_df[report_df['amount'] > 0]  # Only take amounts > 0

    # Merge the two dataframes on transaction_reference (REF) and account/type
    merged_df = pd.merge(
        log_df,
        report_df,
        left_on=['transaction_reference', 'account', 'type'],
        right_on=['REF', 'ACCOUNT', 'type'],
        suffixes=('_log', '_report')
    )

    # Calculate the absolute difference between the amounts
    merged_df['difference'] = abs(merged_df['amount_log']) - abs(merged_df['amount_report'])

    # Identify mismatches where the difference is not zero
    mismatches = merged_df[merged_df['difference'] != 0]

    # Calculate final balances for each account
    final_balances = report_df.groupby('ACCOUNT')['amount'].sum().reset_index()
    final_balances.rename(columns={'amount': 'final_balance'}, inplace=True)

    # Save the mismatches and final balances to separate CSV files
    mismatches.to_csv(mismatches_file_path, index=False)
    final_balances.to_csv(balances_file_path, index=False)

    print(f"Analysis complete. Mismatches saved to {mismatches_file_path}")
    print(f"Final balances saved to {balances_file_path}")

# Run the analysis
analyze_cpf_files(LOGFILE, CPFREPORT, OUTPUT_MISMATCHES, OUTPUT_BALANCES)