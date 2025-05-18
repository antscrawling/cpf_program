from setuptools import setup, find_packages

setup(
    name="cpf_program",
    version="0.1.0",
    description="CPF Program",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        # Add your dependencies here, e.g.:
        # "streamlit",
        # "pandas",
    ],
    include_package_data=True,
    python_requires=">=3.8",
)