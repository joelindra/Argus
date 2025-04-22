# Argus PHPUnit Scanner

A sophisticated security tool designed to detect PHPUnit eval-stdin.php vulnerabilities in web applications. Named after Argus Panoptes, the all-seeing giant with a hundred eyes from Greek mythology, this tool vigilantly watches over web applications to identify vulnerable installations of PHPUnit that could lead to remote code execution.

## 🔍 Features

- **Multi-threaded scanning** for efficient testing of multiple targets
- **Intelligent payload generation** with unique identifiers for accurate validation
- **Multiple vulnerability path checking** across common web application structures
- **Automatic response validation** to confirm actual vulnerabilities
- **Detailed logging** of vulnerable sites and errors
- **Colorful terminal output** with real-time progress tracking
- **Configurable timeout and retry mechanisms** for reliable scanning

## 📋 Requirements

- Python 3.6+
- Required Python packages (see installation section)
- List of target domains/IPs to scan

## 🚀 Installation

1. Clone the repository:
   ```
   git clone https://github.com/joelindra/Argus.git
   cd Argus
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

   Or install dependencies manually:
   ```
   pip install requests colorama tqdm pyfiglet termcolor urllib3
   ```

## 💻 Usage

1. Create a text file containing a list of target websites (one per line)
2. Run the script:
   ```
   python3 argus.py
   ```
3. When prompted, enter:
   - The path to your target list file
   - The number of concurrent threads to use (default: 10)

4. The scanner will begin checking each site for the PHPUnit vulnerability

## 📊 Output

The script creates a `results` directory containing:
- `vulnerable_[timestamp].txt` - Detailed information about vulnerable sites
- `errors_[timestamp].txt` - Error logs for debugging

## 🔍 How It Works

Just as Argus Panoptes kept watch with his hundred eyes, this tool works by:
1. Attempting to access various paths where the vulnerable `eval-stdin.php` file is commonly found
2. Sending specially crafted PHP code that generates a unique fingerprint
3. Analyzing responses to confirm code execution
4. Recording confirmed vulnerabilities for further investigation

## ⚠️ Disclaimer

This tool is intended for legitimate security testing with proper authorization. Using this tool against systems without explicit permission may be illegal. The author is not responsible for any misuse of this software.

## 👨‍💻 Author

**Joel Indra**
- GitHub: [github.com/joelindra](https://github.com/joelindra)

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
