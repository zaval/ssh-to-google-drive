# SSH to Google Drive

A C++ application that facilitates secure file transfers between SFTP servers and Google Drive, 
enabling seamless integration between SSH-accessible systems and cloud storage.

## Overview

This application provides a bridge between SFTP (SSH File Transfer Protocol) servers and Google Drive, 
allowing users to transfer files from SFTP to Google Drive. 
It's particularly useful for automated backups, file synchronization, and cloud storage management for SSH-accessible servers.

## Features

- **SFTP Client**: Connect to remote servers via SSH/SFTP
- **Google Drive Integration**: Upload, download, and manage files on Google Drive
- **MD5 Verification**: Built-in MD5 hashing for file integrity verification
- **Command-line Interface**: Easy-to-use argument parsing for batch operations
- **Cross-platform**: Built with C++20 for modern compatibility

## Project Structure

```
ssh_to_gdrive/
├── main.cpp           # Main application entry point
├── sftpclient.h/.cpp  # SFTP client implementation
├── gdriveapi.h/.cpp   # Google Drive API integration
├── argparser.h/.cpp   # Command-line argument parser
├── md5.h/.cpp         # MD5 hashing utilities
├── CMakeLists.txt     # Build configuration
└── Dockerfile         # Container deployment
```

## Prerequisites

- C++20 compatible compiler (GCC 10+, Clang 12+, or MSVC 2019+)
- CMake 3.16 or higher
- OpenSSL development libraries
- libssh2 development libraries
- Google Cloud Platform account with Drive API enabled

## Installation

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/zaval/ssh-to-google-drive.git
cd ssh_to_gdrive
```

2. Create build directory:
```bash
mkdir build && cd build
```

3. Configure and build:
```bash
cmake ..
make
```

### Using Docker

```bash
docker build -t ssh_to_gdrive .
docker run -it ssh_to_gdrive
```

## Configuration

### Google Drive API Setup

1. Create a Google Cloud Platform project
2. Enable the Google Drive API
3. Create a OAuth 2.0 Client ID or service account

### OAuth 2.0 Client ID

1. Go to the Cloud console → API & Services → Credentials.
2. Create a new TV and Limited Input client.
3. Enable Google Drive API service.

### Service Account 

1. Go to the Cloud console → API & Services → Credentials.
2. Create a new Service account and download the json file.
3. Share the folder to the email from `client_email` field of the service account json file or create a shared drive


## Usage

### Basic Command Structure

```bash
./ssh_to_gdrive [OPTIONS] 
```

### Examples

#### Upload from SFTP to Google Drive
```bash
./ssh_to_gdrive --sftp-host example.com --sftp-user username --sftp-path /remote/file.txt --gdrive-folder "1nuMkAeFFxtOplKk33nP5ajLgZ884oHma"
```


### Command-line Options

- `--sftp-host`: SFTP server hostname or IP address
- `--sftp-user`: SFTP username
- `--sftp-password`: SFTP password (use with caution)
- `--sftp-key`: Path to SSH private key file
- `--sftp-path`: Remote file or directory path
- `--gdrive-folder`: Google Drive folder name (https://drive.google.com/drive/folders/<FOLDER_NAME>)
- `--service-account`: Path to Google service account JSON file (env: GOOGLE_SERVICE_ACCOUNT)
- `--client-id`: OAuth 2.0 Client ID (env: CLIENT_ID)
- `--secret`: OAuth 2.0 Client secret (env: SECRET)

## Security Considerations

- Use SSH key authentication instead of passwords when possible
- Store service account keys securely
- Consider using environment variables for sensitive information
- Implement proper access controls for both SFTP and Google Drive

## Error Handling

The application provides detailed error messages for:
- SFTP connection failures
- Google Drive API errors
- File transfer interruptions
- Authentication issues
- MD5 verification failures

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License

## Support

For issues and questions:
- Create an issue on the project repository
- Check the documentation for troubleshooting tips
- Review the error logs for diagnostic information

## Dependencies

- **cpr**: HTTP requests library
- **jwt-cpp**: JSON Web Token library for Google API authentication
- **spdlog**: Logging library
- **OpenSSL**: Cryptographic functions
- **libssh2**: SSH2 client library