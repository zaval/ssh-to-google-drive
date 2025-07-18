#include "gdriveapi.h"
#include <cpr/cpr.h>
#include <iostream>

#include "jwt-cpp/jwt.h"
#include "spdlog/spdlog.h"


GDriveAPI::GDriveAPI(const std::string& client_id, const std::string& client_secret) :
    client_id_(client_id),
    client_secret_(client_secret)
{
}

GDriveAPI::GDriveAPI(const std::string &service_account_file):
    service_account_(service_account_file)
{
}

bool GDriveAPI::authorize() {

    load_token();
    if (!access_token.empty() && !is_token_expired()) {
        return true;
    }

    if (!refresh_token.empty() && is_token_expired()) {
        return refresh_access_token();
    }

    auto device_code_response = get_device_and_user_codes();
    if (device_code_response == nullptr) {
        return false;
    }

    // Display instructions to the user
    std::cout << "Please go to: " << device_code_response["verification_url"].get<std::string>() << std::endl;
    std::cout << "And enter the code: " << device_code_response["user_code"].get<std::string>() << std::endl;

    auto token_response = poll_for_token(device_code_response["device_code"].get<std::string>());
    if (token_response == nullptr) {
        return false;
    }

    access_token = token_response["access_token"].get<std::string>();
    // IMPORTANT: The refresh token is only provided on the initial authorization.
    if (token_response.contains("refresh_token")) {
        this->refresh_token = token_response["refresh_token"].get<std::string>();
        // You should now PERSIST this refresh_token (e.g., write to a config file)
        // so you don't have to re-authorize every time the app starts.
    }
    if (token_response.contains("expires_in")) {
        token_expires_at = std::chrono::system_clock::now() + std::chrono::seconds(token_response["expires_in"].get<long>() - 30); // Subtract 30s as a buffer
    }

    spdlog::info("Access token successfully obtained.");
    spdlog::info("Access token: {}", access_token);
    spdlog::info("Refresh token: {}", refresh_token);
    // std::cout << "\nAccess Token: " << access_token << std::endl;
    // std::cout << "Refresh Token (store this securely!): " << refresh_token << std::endl;

    save_token();

    return true;

}

bool GDriveAPI::refresh_access_token() {
    if (refresh_token.empty()) {
        spdlog::error("Error: No refresh token available. Please re-authorize.");
        // std::cerr << "Error: No refresh token available. Please re-authorize." << std::endl;
        return false;
    }
    if (refresh_token == "SERVICE_ACCOUNT_REFRESH_TOKEN") {
        return authorize_from_service_account();
    }
    spdlog::info("Refreshing access token...");

    // std::cout << "Access token expired. Refreshing..." << std::endl;

    cpr::Response r = cpr::Post(cpr::Url{GOOGLE_TOKEN_URL},
                                cpr::Payload{
                                    {"client_id", client_id_},
                                    {"client_secret", client_secret_},
                                    {"refresh_token", refresh_token},
                                    {"grant_type", "refresh_token"} // This grant_type is crucial!
                                });

    if (r.status_code != 200) {
        spdlog::error("Error refreshing access token. Server responded with: {}", r.status_code);
        // std::cerr << "Error refreshing access token. Server responded with: "
        //           << r.status_code << std::endl;
        spdlog::error("Error message: {}", r.text);
        // std::cerr << r.text << std::endl;
        // If refreshing fails (e.g., token revoked), you must re-authorize.
        return false;
    }

    nlohmann::json response_json = nlohmann::json::parse(r.text);

    // Store the new access token and its new expiry time
    this->access_token = response_json["access_token"].get<std::string>();
    const auto expires_in_seconds = response_json["expires_in"].get<long>();
    this->token_expires_at = std::chrono::system_clock::now() + std::chrono::seconds(expires_in_seconds - 30); // Subtract 30s as a buffer

    save_token();

    spdlog::info("Access token refreshed.");
    // std::cout << "Access token successfully refreshed." << std::endl;
    return true;

}

bool GDriveAPI::is_token_expired() const {
    return std::chrono::system_clock::now() >= token_expires_at;
}

void GDriveAPI::list_files() {
    if (access_token.empty()) {
        spdlog::error("Not authorized. Please call authorize() first.");
        // std::cerr << "Not authorized. Please call authorize() first." << std::endl;
        return;
    }

    // Check if the token has expired, and if so, refresh it.
    if (is_token_expired()) {
        if (!refresh_access_token()) {
            spdlog::error("Could not refresh token. Please re-authorize.");
            // std::cerr << "Could not refresh token. Please re-authorize." << std::endl;
            return;
        }
    }

    // Now, proceed with the API call using the valid access_token
    // cpr::Response r = cpr::Get(cpr::Url{"https://www.googleapis.com/drive/v3/files/1Ir73Tx3O3MIVlNpU60TOz64n9rvl50E4"},
    cpr::Response r = cpr::Get(cpr::Url{"https://www.googleapis.com/drive/v3/files"},
                               cpr::Header{{"Authorization", "Bearer " + this->access_token}},
                               cpr::Header{{"Accept", "application/json"}}
                               );

    if (r.status_code == 200) {
        // std::cout << "Successfully fetched file list:" << std::endl;
        std::cout << nlohmann::json::parse(r.text).dump(4) << std::endl;
    } else {
        spdlog::error("Error fetching files: {}", r.status_code);
        // std::cerr << "Error fetching files: " << r.status_code << std::endl;
        spdlog::error("Error message: {}", r.text);
        // std::cerr << r.text << std::endl;
    }

}

nlohmann::json GDriveAPI::get_file_info(const std::string &file_id) {
    if (access_token.empty()) {
        spdlog::error("Not authorized. Please call authorize() first.");
        // std::cerr << "Not authorized. Please call authorize() first." << std::endl;
        return {};
    }

    // Check if the token has expired, and if so, refresh it.
    if (is_token_expired()) {
        if (!refresh_access_token()) {
            spdlog::error("Could not refresh token. Please re-authorize.");
            // std::cerr << "Could not refresh token. Please re-authorize." << std::endl;
            return {};
        }
    }

    cpr::Response r = cpr::Get(cpr::Url{"https://www.googleapis.com/drive/v3/files/" + file_id},
                               cpr::Header{{"Authorization", "Bearer " + this->access_token}},
                               cpr::Header{{"Accept", "application/json"}}
                               );

    if (r.status_code == 200) {
        // std::cout << "Successfully fetched file list:" << std::endl;
        return  nlohmann::json::parse(r.text).dump(4);
    } else {
        spdlog::error("Error fetching files: {}", r.status_code);
        // std::cerr << "Error fetching files: " << r.status_code << std::endl;
        spdlog::error("Error message: {}", r.text);
        // std::cerr << r.text << std::endl;
        return {};
    }
}

std::string GDriveAPI::create_folder(const std::string &folder_name) {
    return create_folder(folder_name, "");
}

std::string GDriveAPI::create_folder(const std::string &folder_name, const std::string &parent_id) {

    if (access_token.empty()) {
        spdlog::error("Not authorized. Please call authorize() first.");
        // std::cerr << "Not authorized. Please call authorize() first." << std::endl;
        return "";
    }

    // Check if the token has expired, and if so, refresh it.
    if (is_token_expired()) {
        if (!refresh_access_token()) {
            spdlog::error("Could not refresh token. Please re-authorize.");
            // std::cerr << "Could not refresh token. Please re-authorize." << std::endl;
            return "";
        }
    }
    nlohmann::json payload = {
        {"name", folder_name},
        {"mimeType", "application/vnd.google-apps.folder"},
    };
    if (!parent_id.empty()) {
        payload["parents"] = {parent_id};
    }

    cpr::Response r = cpr::Post(
            cpr::Url{"https://www.googleapis.com/drive/v3/files"},
            cpr::Body{payload.dump()},
            cpr::Header{{"Authorization", "Bearer " + this->access_token}},
            cpr::Header{{"Accept", "application/json"}},
            cpr::Header{{"Content-Type", "application/json"}}
        );
    if (r.status_code == 200) {
        spdlog::info("Successfully created folder: {}", folder_name);
        // std::cout << "Successfully created folder:" << std::endl;
        return nlohmann::json::parse(r.text)["id"];
    } else {
        spdlog::error("Error creating folder: {}", r.status_code);
        // std::cerr << "Error creating folder: " << r.status_code << std::endl;
        spdlog::error("Error message: {}", r.text);
        // std::cerr << r.text << std::endl;
        return "";
    }
}

std::string GDriveAPI::create_file(const std::string &file_name, const std::string &mime_type,
    const std::string &parent_id) {
    if (access_token.empty()) {
        spdlog::error("Not authorized. Please call authorize() first.");
        // std::cerr << "Not authorized. Please call authorize() first." << std::endl;
        return "";
    }

    // Check if the token has expired, and if so, refresh it.
    if (is_token_expired()) {
        if (!refresh_access_token()) {
            spdlog::error("Could not refresh token. Please re-authorize.");
            // std::cerr << "Could not refresh token. Please re-authorize." << std::endl;
            return "";
        }
    }
    nlohmann::json payload = {
        {"name", file_name},
        {"mimeType", mime_type},
    };
    if (!parent_id.empty()) {
        payload["parents"] = {parent_id};
    }

    cpr::Response r = cpr::Post(
            cpr::Url{"https://www.googleapis.com/drive/v3/files"},
            cpr::Body{payload.dump()},
            cpr::Header{{"Authorization", "Bearer " + this->access_token}},
            cpr::Header{{"Accept", "application/json"}},
            cpr::Header{{"Content-Type", "application/json"}}
        );
    if (r.status_code == 200) {
        spdlog::info("Successfully created file: {}", file_name);
        // std::cout << "Successfully created file:" << std::endl;
        return nlohmann::json::parse(r.text)["id"];
    } else {
        spdlog::error("Error creating file: {}", r.status_code);
        // std::cerr << "Error creating file: " << r.status_code << std::endl;
        spdlog::error("Error message: {}", r.text);
        // std::cerr << r.text << std::endl;
        return "";
    }
}

std::string GDriveAPI::create_file_for_upload(const std::string &filename, const std::string& parent_id)  {

    if (access_token.empty()) {
        spdlog::error("Not authorized. Please call authorize() first.");
        // std::cerr << "Not authorized. Please call authorize() first." << std::endl;
        return {};
    }

    // Check if the token has expired, and if so, refresh it.
    if (is_token_expired()) {
        if (!refresh_access_token()) {
            spdlog::error("Could not refresh token. Please re-authorize.");
            // std::cerr << "Could not refresh token. Please re-authorize." << std::endl;
            return {};
        }
    }
    nlohmann::json payload = {
        {"name", filename},
        {"mimeType", "application/octet-stream"},
    };
    if (!parent_id.empty()) {
        payload["parents"] = {parent_id};
    }

    cpr::Response r = cpr::Post(
        cpr::Url{"https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable"},
        cpr::Body{payload.dump()},
        cpr::Header{{"Authorization", "Bearer " + this->access_token}},
        // cpr::Header{{"X-Upload-Content-Type", "application/octet-stream"}},
        cpr::Header{{"Content-Type", "application/json; charset=UTF-8"}}
    );
    if (r.status_code == 200) {
        // std::cout << "Successfully created file" << std::endl;
        return r.header["Location"];
    } else {
        spdlog::error("Error creating file: {}", r.status_code);
        // std::cerr << "Error creating file: " << r.status_code << std::endl;
        spdlog::error("Error message: {}", r.text);
        // std::cerr << r.text << std::endl;
        return "";
    }
}

FileChunkResponse GDriveAPI::upload_file_chunk(const std::string &upload_url, char *data, size_t size, size_t offset,
    size_t total_size) {
    if (access_token.empty()) {
        spdlog::error("Not authorized. Please call authorize() first.");
        // std::cerr << "Not authorized. Please call authorize() first." << std::endl;
        return {false, ""};
    }

    // Check if the token has expired, and if so, refresh it.
    if (is_token_expired()) {
        if (!refresh_access_token()) {
            spdlog::error("Could not refresh token. Please re-authorize.");
            // std::cerr << "Could not refresh token. Please re-authorize." << std::endl;
            return {false, ""};
        }
    }

    const auto content_range = "bytes " + std::to_string(offset) + "-" + std::to_string(offset + size - 1) + "/" + std::to_string(total_size);

    // std::cout << "Upload chunk: " << content_range << std::endl;
    cpr::Response r = cpr::Put(
        cpr::Url{upload_url},
        cpr::Body{data, size},
        cpr::Header{{"Authorization", "Bearer " + this->access_token}},
        cpr::Header{{"Content-Length", std::to_string(size)}},
        cpr::Header{{"Content-Range", content_range}}
    );

    if (r.status_code != 200 && r.status_code != 201 && r.status_code != 308) {
        spdlog::error("Error uploading file chunk: {}", r.status_code);
        // std::cerr << "Error uploading file chunk: " << r.status_code << std::endl << r.text << std::endl;
        return {false, ""};
    }

    if (r.status_code == 200) {
        const auto response = nlohmann::json::parse(r.text);
        if (response.contains("id")) {
            return {true, response["id"].get<std::string>()};
        } else {
            return {true, ""};
        }
        // spdlog::info("File chunk uploaded successfully");
        // std::cout << "File uploaded successfully" << std::endl;
    }

    // std::cout << "Upload chunk response: " << r.status_code << std::endl << r.text << std::endl;
    // for (const auto& header : r.header) {
    //     std::cout << header.first << ": " << header.second << std::endl;
    // }
    return {true, ""};
}

std::string GDriveAPI::get_file_md5(const std::string &file_id) {
    if (access_token.empty()) {
        spdlog::error("Not authorized. Please call authorize() first.");
        // std::cerr << "Not authorized. Please call authorize() first." << std::endl;
        return "";
    }

    // Check if the token has expired, and if so, refresh it.
    if (is_token_expired()) {
        if (!refresh_access_token()) {
            spdlog::error("Could not refresh token. Please re-authorize.");
            // std::cerr << "Could not refresh token. Please re-authorize." << std::endl;
            return "";
        }
    }

    cpr::Response r = cpr::Get(cpr::Url{"https://www.googleapis.com/drive/v3/files/" + file_id},
                               cpr::Header{{"Authorization", "Bearer " + this->access_token}},
                               cpr::Header{{"Accept", "application/json"}},
                               cpr::Parameters{{"fields", "md5Checksum"}}
                               );

    if (r.status_code == 200) {
        // std::cout << "Successfully fetched file list:" << std::endl;
        const auto response = nlohmann::json::parse(r.text);
        if (response.contains("md5Checksum")) {
            return response["md5Checksum"].get<std::string>();
        } else {
            return "";
        }
    } else {
        spdlog::error("Error fetching file md5: {}", r.status_code);
        // std::cerr << "Error fetching files: " << r.status_code << std::endl;
        spdlog::error("Error message: {}", r.text);
        // std::cerr << r.text << std::endl;
        return "";
    }
}

bool GDriveAPI::authorize_from_service_account() {
    std::ifstream key_file(service_account_);
    if (!key_file.is_open()) {
        spdlog::error("Error: Could not open service account key file.");
        // std::cerr << "Error: Could not open service account key file." << std::endl;
        return false;
    }
    nlohmann::json credentials = nlohmann::json::parse(key_file);
    const std::string private_key = credentials["private_key"];
    const std::string client_email = credentials["client_email"];
    const std::string token_uri = credentials["token_uri"];

    // 2. Create the JWT
    auto token = jwt::create()
        .set_issuer(client_email)
        .set_subject(client_email) // Can also be a user to impersonate
        .set_audience(token_uri)
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
        .set_payload_claim("scope", jwt::claim(std::string("https://www.googleapis.com/auth/drive")))
        .sign(jwt::algorithm::rs256("", private_key, "", "")); // Sign with the private key

    // 3. Exchange the JWT for an access token using cpr
    cpr::Response r = cpr::Post(cpr::Url{token_uri},
                                cpr::Payload{
                                    {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
                                    {"assertion", token}
                                });
    if (r.status_code != 200) {
        spdlog::error("Error getting access token: {}", r.status_code);
        // std::cerr << "Error getting access token: " << r.status_code << std::endl;
        spdlog::error("Response: {}", r.text);
        // std::cerr << "Response: " << r.text << std::endl;
        return false;
    }
    nlohmann::json response_json = nlohmann::json::parse(r.text);
    access_token = response_json["access_token"];
    if (response_json.contains("expires_in")) {
        token_expires_at = std::chrono::system_clock::now() + std::chrono::seconds(response_json["expires_in"].get<long>() - 30); // Subtract 30s as a buffer
    }
    refresh_token = "SERVICE_ACCOUNT_REFRESH_TOKEN";
    return true;

}

void GDriveAPI::save_token() {

    nlohmann::json j;
    j["access_token"] = access_token;
    j["refresh_token"] = refresh_token;
    j["expires_in"] = std::chrono::duration_cast<std::chrono::seconds>(token_expires_at.time_since_epoch()).count();
    std::ofstream file("gdrive_token.json");
    file << j.dump(4);
    file.close();
}

void GDriveAPI::load_token() {
    if (std::ifstream file("gdrive_token.json"); file.is_open()) {
        nlohmann::json j;
        file >> j;
        access_token = j["access_token"].get<std::string>();
        refresh_token = j["refresh_token"].get<std::string>();
        if (j.contains("expires_in"))
            token_expires_at = std::chrono::system_clock::time_point(std::chrono::seconds(j["expires_in"].get<long>()));
    }
}

nlohmann::json GDriveAPI::get_device_and_user_codes() {
    cpr::Response r = cpr::Post(cpr::Url{GOOGLE_DEVICE_CODE_URL},
                                cpr::Payload{
                                    {"client_id", client_id_},
                                    // This scope gives full read/write access to a user's Drive.
                                    // For read-only, you could use: https://www.googleapis.com/auth/drive.readonly
                                    {"scope", "https://www.googleapis.com/auth/drive.file"}
                                });

    if (r.status_code != 200) {
        spdlog::error("Error getting device code: {}", r.status_code);
        // std::cerr << "Error getting device code: " << r.status_code << std::endl;
        spdlog::info("{}", r.text);
        // std::cerr << r.text << std::endl;
        return nullptr;
    }

    return nlohmann::json::parse(r.text);
}

nlohmann::json GDriveAPI::poll_for_token(const std::string &device_code) {
    while (true) {
        // Wait for 5 seconds before the next poll, as recommended by Google's API
        std::this_thread::sleep_for(std::chrono::seconds(5));

        cpr::Response r = cpr::Post(cpr::Url{GOOGLE_TOKEN_URL},
                                    cpr::Payload{
                                        {"client_id", client_id_},
                                        {"client_secret", client_secret_},
                                        {"device_code", device_code},
                                        {"grant_type", "urn:ietf:params:oauth:grant-type:device_code"}
                                    });

        spdlog::info("Token response: {}", r.text);
        // std::cout << "token response: " << std::endl << r.text << std::endl;
        nlohmann::json response_json = nlohmann::json::parse(r.text);

        if (r.status_code == 200) {
            // Success! The user has granted access.
            spdlog::info("Access granted!");
            // std::cout << "Access granted!" << std::endl;
            return response_json;
        }

        // Check for specific errors
        if (response_json.contains("error")) {
            const std::string error = response_json["error"];
            if (error == "authorization_pending") {
                // This is expected, the user hasn't finished yet. Continue polling.
                spdlog::info("Waiting for user authorization...");
                // std::cout << "Waiting for user authorization..." << std::endl;
            } else if (error == "slow_down") {
                // We are polling too fast. Increase the interval.
                std::this_thread::sleep_for(std::chrono::seconds(5));
            } else {
                // A definitive error occurred (e.g., "access_denied").
                spdlog::error("Error polling for token: {}", error);
                // std::cerr << "Error polling for token: " << error << std::endl;
                return nullptr;
            }
        }
    }
}
