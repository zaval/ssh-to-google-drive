#ifndef GDRIVEAPI_H
#define GDRIVEAPI_H

#include <string>
#include <nlohmann/json.hpp>
#include <mutex>


const std::string GOOGLE_DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code";
const std::string GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

struct FileChunkResponse {
    bool success;
    std::string file_id;
};


/**
 * @class GDriveAPI
 * @brief Represents an interface to interact with Google Drive using its API.
 *
 * The GDriveAPI class provides functionalities for authenticating with Google Drive,
 * uploading, downloading, listing, and managing files and folders in a Google Drive account.
 * This class handles API requests and responses, ensuring seamless integration with Google Drive.
 *
 * To use this class, ensure you have valid API credentials and necessary permissions.
 */
class GDriveAPI {
public:
    GDriveAPI(const std::string& client_id, const std::string& client_secret);
    explicit GDriveAPI(const std::string& service_account_file);

    /**
     * @brief Authorizes the application to access the user's account.
     *
     * This method handles the authentication process required for the application to interact
     * with a specific user's account by obtaining the necessary access tokens.
     * It ensures secure and validated access by complying with authentication protocols.
     *
     * @return A boolean value indicating whether the authorization was successful.
     */
    bool authorize();

    /**
     * @brief Authorizes the application using a service account.
     *
     * The authorize_from_service_account method utilizes the provided service account
     * credentials to generate an authentication token. This token is then used to
     * authenticate API requests made by the application. Service accounts are typically
     * used for server-to-server communication without user intervention.
     *
     * @return Returns a boolean indicating the success or failure of the authentication process.
     * True if the authorization is successful, otherwise false.
     */
    bool authorize_from_service_account();

    /**
     * @brief Refreshes the expired access token to maintain authenticated sessions.
     *
     * This method communicates with the authentication server to generate a new
     * access token using a valid refresh token. It ensures uninterrupted access
     * to the API services by renewing the expired access token.
     *
     * Proper error handling must be implemented to address any issues during the
     * token refresh process.
     *
     * @return A new access token in case of a successful refresh, or an error
     * message if the refresh operation fails.
     */
    bool refresh_access_token();


    /**
     * @fn list_files
     * @brief Retrieves a list of files from a specific directory or location.
     *
     * This method is responsible for querying and returning a collection of files stored
     * in the specified directory. It may include support for filtering, sorting, or paginating
     * the file list based on provided parameters or constraints.
     *
     * The method is typically used to display or manage the contents of a directory, allowing
     * users or applications to access information about available files.
     *
     * Proper permissions and access rights may be required to successfully retrieve the file list.
     */
    void list_files();

    /**
     * @brief Retrieves information about a specified file.
     *
     * The get_file_info function fetches detailed metadata of a file, such as its name, size,
     * type, and last modified date, from the storage system or API backend. This function
     * is useful for obtaining the file's attributes for further processing or display.
     *
     * @param file_id The unique identifier of the file whose information needs to be retrieved.
     *                It should be a valid identifier recognized by the storage system or API.
     * @return A structure or object containing the file's metadata, or an error response
     *         if the file cannot be found or the retrieval fails.
     */
    nlohmann::json get_file_info(const std::string& file_id);

    /**
     * @brief Creates a folder in Google Drive with the specified name.
     *
     * This method interacts with the Google Drive API to create a new folder
     * in the user's drive. It requires a valid authentication token and
     * appropriate permissions. The folder creation can fail if the token is
     * invalid, the user lacks permissions, or due to network errors.
     *
     * @param folder_name The name of the folder to be created.
     * @return A boolean indicating the success or failure of the folder creation operation.
     */
    std::string create_folder(const std::string& folder_name);

    /**
     * @brief Creates a new folder in the specified location in Google Drive.
     *
     * This method allows users to create a new folder by specifying the intended
     * folder name and its parent folder ID. The created folder will be available
     * in the user's Google Drive and can be further managed through the API.
     *
     * @param folder_name The name of the folder to be created.
     * @param parent_id The ID of the parent folder where the new folder will be created.
     *                  If null or empty, the folder will be created in the root directory.
     * @return The ID of the newly created folder if successful, or an error message on failure.
     */
    std::string create_folder(const std::string& folder_name, const std::string& parent_id);

    /**
     * @brief Creates a new file with the specified name and content.
     *
     * This method is responsible for creating a file in Google Drive
     *
     * @param file_name The name of the file to be created.
     * @param mime_type The MIME type of the file
     * @param parent_id The ID of the parent folder where the new file will be created.
     *                  If null or empty, the folder will be created in the root directory.
     * @return ID of the new created file.
     */
    std::string create_file(const std::string& file_name, const std::string& mime_type = "text/plain", const std::string& parent_id = "");

    /**
     * @brief Creates a file
     *
     * This method is responsible for generating a Drive file
     * It ensures the file is properly created and prepared
     * for the upload process.
     *
     * @param filename The name of the file to be created.
     * @param parent_id The ID of the parent folder where the new file will be created.
     *                  If null or empty, the folder will be created in the root directory.
     * @return URL that will be used to upload file content
     */
    std::string create_file_for_upload(const std::string& filename, const std::string& parent_id);

    /**
     * @brief Uploads a chunk of a file to a storage server.
     *
     * This method allows uploading a specific chunk of a file in a multipart or chunked upload process.
     * It ensures the data integrity of each chunk and validates the upload process.
     * Use this method as part of a larger process to handle large file uploads efficiently.
     *
     * @param upload_url The url to upload
     * @param data The data of the current chunk to be uploaded.
     * @param size The size of the current chunk being uploaded.
     * @param offset The position of the chunk within the file (in bytes).
     * @param total_size The total size of the file (in bytes).
     * @return {true, file_id} if the chunk is successfully uploaded, otherwise false.
     */
    FileChunkResponse upload_file_chunk(const std::string& upload_url, char *data, size_t size, size_t offset, size_t total_size);


    /**
     * @fn std::string get_file_md5(const std::string& file_path)
     * @brief Computes the MD5 hash of the specified file.
     *
     * This function reads the contents of the given file and calculates its MD5 checksum.
     * It is useful for verifying file integrity or comparing files based on their content.
     *
     * @param file_id The Google Drive's file id whose MD5 hash needs to be calculated.
     * @return A string representing the MD5 hash of the file.
     */
    std::string get_file_md5(const std::string& file_id);


private:
    nlohmann::json get_device_and_user_codes();
    nlohmann::json poll_for_token(const std::string& device_code);
    void save_token();
    void load_token();
    bool is_token_expired() const;


    std::string access_token;
    std::string refresh_token; // IMPORTANT: This should be saved securely for long-term use.
    std::chrono::time_point<std::chrono::system_clock> token_expires_at;

    std::string client_id_;
    std::string client_secret_;
    std::string service_account_;

    std::mutex token_mutex;
};



#endif //GDRIVEAPI_H
