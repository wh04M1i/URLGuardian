# URLGuardian

URLGuardian is a Python tool that scans IP addresses and URLs on VirusTotal, providing security analysis and scan results. It's designed to help you assess the safety of web resources and detect potential threats.

## Features

- Scan IP addresses and URLs on VirusTotal.
- Retrieve detailed scan reports for each resource.
- Store scan results in a user-specified output file.
- Supports plain text input files with one IP address or URL per line.
- Provides information such as detection ratio, antivirus engines results, and additional metadata.

## Prerequisites

Before using URLGuardian, you'll need the following:

- Python 3.x
- VirusTotal API key (Get it [here](https://www.virustotal.com/))

## Getting Started

1. Clone or download the URLGuardian repository to your local machine.

2. Install the required libraries using pip:

   ```
   pip install requests
   ```

3. Obtain a VirusTotal API key by signing up at [VirusTotal](https://www.virustotal.com/). Replace `'YOUR_API_KEY'` in the script with your actual API key.

4. Prepare an input file (`input.txt`) containing the list of IP addresses and URLs to be scanned. One IP address or URL should be listed on each line.

5. Run the URLGuardian script:

   ```
   python urlguardian.py
   ```

6. Scan results will be saved in the `output.txt` file, including detection results, detection ratio, and metadata for each resource.

## Customization

You can customize the script by adjusting the input and output file paths to meet your specific requirements.

## Author

- Goverdhan Kumar


## Acknowledgments

- This tool is built using Python and the VirusTotal API.
- Special thanks to the open-source community for inspiration and resources.

## Contact

For questions or support, please contact pandeygoverdhan@proton.me.

