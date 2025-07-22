#ifndef SFTPCLIENT_H
#define SFTPCLIENT_H
#include <string>
#include <libssh/libssh.h>

#include <filesystem>
#include <libssh/sftp.h>
#include <vector>

namespace fs = std::filesystem;

enum SFTP_FILE_TYPE {
    FILE_TYPE,
    DIRECTORY_TYPE
};

struct SFTPEntry {
    std::string name;
    SFTP_FILE_TYPE type;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    uint32_t permissions;
    uint64_t atime64;
    uint64_t createtime;
    uint64_t mtime64;
};

/**
 * @class SFTPClient
 * @brief Provides functionality to interact with an SFTP server.
 *
 * The SFTPClient class is a utility for establishing secure file transfer
 * connections using the SFTP protocol. It enables the uploading, downloading,
 * and removal of files as well as directory management on a remote SFTP server.
 *
 * The class handles authentication, session management, and error handling
 * to facilitate seamless communication with the server.
 */
class SFTPClient {

public:
    SFTPClient(const std::string &hostname, const int &port);
    ~SFTPClient();

    /**
     * @brief Establishes a connection to the server.
     *
     * This method initiates a connection to the specified server using
     * the provided connection parameters. It ensures proper authentication
     * and prepares the session for further communication.
     *
     * @param username The username used for authentication.
     * @param password The password used for authentication.
     * @return True if the connection is successfully established, otherwise false.
     */
    bool connect(const std::string &username, const std::string &password);

    /**
     * @brief Establishes a connection to a remote server.
     *
     * The connect method initializes and opens a connection to the specified
     * remote server. It ensures the necessary authentication and network
     * setup is completed for further communication. This method is a
     * prerequisite for executing any operations on the server.
     *
     * @param username The username used for authentication.
     * @param key_file The path to the private key.
     * @param password The password associated with the specified username.
     * @return True if the connection is successfully established, otherwise false.
     */
    bool connect(const std::string &username, const fs::path &key_file, const std::string &password = "");

    /**
     * @fn ls
     * @brief Lists the contents of a directory on the filesystem.
     *
     * The ls function retrieves and returns a list of all files and directories
     * within the specified directory path. It can be used to inspect or verify
     * the contents of a directory and supports error handling for invalid paths.
     *
     * @param path The directory path whose contents are to be listed.
     * @return A list of filenames and subdirectories within the specified path.
     */
    std::vector<SFTPEntry> ls(const std::string &path);

    /**
     * @brief Opens a file for reading or writing based on the specified mode.
     *
     * This method provides functionality to open a file by its name and
     * prepare it for operations like reading or writing depending on the given mode.
     * It ensures proper error handling in case the file cannot be accessed
     * or opened successfully.
     *
     * @param path The name of the file to be opened.
     * @param mode The mode in which the file should be opened, such as read or write.
     * @return True if the file is opened successfully, otherwise false.
     */
    sftp_file open_file(const std::string &path, const int &mode);


    /**
     * @brief Closes an opened file resource.
     *
     * The close_file method ensures that an opened file is properly closed
     * and its resources are released. This is essential for avoiding resource
     * leaks and ensuring the integrity of data.
     *
     * It is recommended to call this method explicitly after all necessary
     * file operations are completed.
     *
     * @param file The handle or reference to the file that needs to be closed.
     * @return True if the file was successfully closed, false otherwise.
     */
    bool close_file(sftp_file file) const;


    /**
     * @brief Reads data from a remote file in chunks.
     *
     * This method reads data from a specified SFTP file into a buffer up to
     * the given chunk size. It handles partial reads, ensuring that data is
     * read iteratively until either the desired chunk size is met or EOF is
     * encountered. Errors during reading are logged appropriately.
     *
     * @param read_bytes Reference to a variable that will store the total number of bytes read.
     * @param file The SFTP file handle to read from.
     * @param buffer The destination buffer to store the read data.
     * @param chunk_size The maximum size of data (in bytes) to read during a single operation.
     */
    void read_file(long &read_bytes, const sftp_file &file, char *buffer, const size_t &chunk_size) const;


    /**
     * @brief Specifies a set of file patterns to ignore in operations.
     *
     * This method allows the user to define a list of file patterns that should
     * be excluded from various file manipulation or processing tasks. Patterns
     * can be specified using wildcard characters or other suitable matching criteria.
     *
     * @param ignore_files A list of strings representing file regexp to ignore during operations.
     */
    void set_ignore_files(const std::vector<std::string> &ignore_files);


    /**
     * @brief Sets the list of files that have been processed.
     *
     * This function updates the internal record of processed files. It is
     * typically used to mark specific files as processed during batch operations
     * or after a certain task has completed. The processed files are stored for
     * further reference or to prevent redundant processing.
     *
     * @param files A collection of file paths representing the files that have been processed.
     */
    void set_processed_files(const std::vector<std::string> &files);

private:
    ssh_session session;
    std::string hostname;
    int port;
    bool connect_to_host() const;
    bool init_sftp();
    sftp_session sftp;
    std::vector<std::string> ignore_files;
    std::vector<std::string> processed_files;
};



#endif //SFTPCLIENT_H
