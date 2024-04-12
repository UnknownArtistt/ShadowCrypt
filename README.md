# ShadowCrypt

<img src="Banner/shadowcryptbanner.png">

ShadowCrypt is a terminal based password manager developed in C++. The program is prepared to run in Linux. The usage on Windows is possible but before installing it you need to download some dependencies (cryptopp, figlet and a c++ compiler). If the dependencies are downloaded is possible to compile and run the program but is recommended to have a Linux distro like Ubuntu for a proper experience.

## Important Information (Please read it)

The program creates files to serve as password libraries, with .txt files being the preferred format due to their ease of handling. Please be aware that the program is designed to generate and encrypt passwords within these files. Due to the encryption process, the files may contain special characters and symbols that some text editors are unable to properly display.

<b>I strongly advise against manually editing your password library files.</b> Tampering with these files can corrupt the data and compromise the security of your passwords. If there is a need to open or edit these files, we recommend using <b>Sublime Text</b>. This editor is capable of displaying encrypted characters by converting them to hexadecimal code, reducing the risk of file corruption.

## Disclaimer

The ShadowCrypt software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors, copyright holders, or contributors be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the Software or the use or other dealings in the Software.

This Software is intended for educational and informational purposes only. It is the responsibility of the user to ensure their use of the Software complies with all applicable laws and regulations. The developer of this Software does not endorse or encourage any illegal use of the Software, nor will they be responsible for any such use by others.

By using the Software, you acknowledge and agree that you have read this disclaimer, understand it, and agree to be bound by its terms. The user assumes all responsibility and risk for the use of this Software. The developer disclaims all liability for any damage, direct or indirect, resulting from the use of the Software.


## Context

In an era where digital security breaches are not just common but expected, the significance of having a strong, secure password cannot be overstated. Passwords are often the first line of defense in protecting personal, financial, and professional information from unauthorized access. Despite this, many individuals continue to use weak, easily guessable passwords, putting their digital lives at risk.

A secure password acts as a robust barrier against hackers and malicious software. It ensures that your private data remains confidential, safeguarding everything from your email accounts to bank details. However, creating and remembering complex passwords can be challenging. This is where our program steps in, offering a solution that not only generates strong, unique passwords for each of your accounts but also encrypts them and stores them in your pc.

The creation of the program has a unique goal, let to know the importance of using strong passwords and the importance of being cautious with them. Getting strong and secure passwords is important but encrypting them gives an extra security measure to avoid attacks.

## Technical Aspects

ShadowCrypt can handle operations like:
- Creating password libraries in your pc
- Generating safe and random passwords
- Encrypting and decrypting the passwords that have been generated
- Visualizing your passwords

For security reasons the encryption and decryption aspects are reserved. Same happens with the password generation specifications.

## Installation

To use ShadowCrypt you only need to download the program and compile it. You can use the bash script or you can compile it on your own. Is important to know that you will need a c/c++ compiler, cryptopp and figlet to use the program in its whole.

First create/go to the directory where you want to clone the repository

Then download the source code or clone the repository:

<b>git clone https://github.com/Julen-H/ShadowCrypt</b>

### Manual Compilation

In Linux you should have already installed the gcc compiler. If you don´t have it you can do this way:

<b>sudo apt update && sudo apt install build-essential</b>

Or you can do it like this:

<b>sudo apt-get update && sudo apt-get install g++ -y</b>

To install cryptopp you can use this command:

<b>sudo apt-get update && sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils -y</b>

Finally you can install figlet in this way:

<b>sudo apt-get update && sudo apt-get install figlet -y</b>

Once the dependecies are downloaded you will need to compile it:

- Compile it -> <b>g++ -c PasswordManager.cpp</b> and later <b>g++ -o ShadowCrypt main.cpp PasswordManager.o -lcryptopp</b>
- Run it -> <b>./ShadowCrypt</b>

### Bash Script

Give execution permissions:

<b>chmod +x ShadowCrypt.sh</b> 

Then execute it:

<b>./ShadowCrypt.sh</b>

Once is executed you can run it using the executable that will create the script (if you use the script every time you want to run the program the script will verify and try to install all the dependencies and will compile the program again):

<b>./ShadowCrypt</b>


