#include "argparser.h"

#include <iostream>

#include "spdlog/spdlog.h"


ArgParser::ArgParser(int argc, char **argv): args(argv + 1, argv + argc) {
}

ProgramOptions ArgParser::parse() const {
    ProgramOptions options{};
    for (const auto &arg: args) {
        if (arg == "-h" || arg == "--help") {
            options.show_help = true;
            return options;
        } if (arg.find("--service-account-file=") == 0) {
            options.service_account_file = arg.substr(23);
        } else if (arg.find("--sa-file=") == 0) {
            options.service_account_file = arg.substr(10);
        } else if (arg.find("--client-id=") == 0) {
            options.client_id = arg.substr(12);
        } else if (arg.find("--secret=") == 0) {
            options.secret = arg.substr(9);
        } else if (arg.find("--ssh-host=") == 0) {
            options.ssh_host = arg.substr(11);
        } else if (arg.find("--ssh-user=") == 0) {
            options.ssh_user = arg.substr(11);
        } else if (arg.find("--ssh-port=") == 0) {
            options.ssh_port = std::stoi(arg.substr(11));
        } else if (arg.find("--ssh-keyfile=") == 0) {
            options.ssh_keyfile = arg.substr(14);
        } else if (arg.find("--gdrive-folder=") == 0) {
            options.gdrive_folder = arg.substr(16);
        } else if (arg.find("--ssh-folder=") == 0) {
            options.ssh_folder = arg.substr(13);
        } else if (arg.find("--ssh-password=") == 0) {
            options.ssh_password = arg.substr(15);
        } else if (arg.find("--ssh-keyfile-password=") == 0) {
            options.ssh_keyfile_password = arg.substr(23);
        } else if (arg.find("--ignore=") == 0) {
            options.ignore.push_back(arg.substr(9));
        } else {
            spdlog::info("Unknown argument: {}", arg);
            // std::cout << "Unknown argument: " << arg << std::endl;
        }
    }

    if (!options.service_account_file.empty()) {
        options.secret = "";
    }

    if (options.gdrive_folder.empty()) {
        throw std::runtime_error("Error: --gdrive-folder is required");
    }

    if (options.ssh_host.empty()) {
        throw std::runtime_error("Error: --ssh-host is required");
    }
    if (options.ssh_user.empty()) {
        throw std::runtime_error("Error: --ssh-user is required");
    }

    if (options.client_id.empty() && options.service_account_file.empty()) {
        options.client_id = std::string(getenv("CLIENT_ID"));
    }
    if (options.secret.empty() && options.service_account_file.empty()) {
        options.secret = std::string(getenv("SECRET"));
    }

    return options;
}

void ArgParser::print_help() {
    std::cout << "Usage: ssh-to-gdrive [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --service-account-file=FILE/--sa-file=FILE      Path to service account JSON file" << std::endl;
    std::cout << "  --client-id=ID                      Google OAuth2 client ID" << std::endl;
    std::cout << "  --secret=SECRET                     Google OAuth2 client secret" << std::endl;
    std::cout << "  --ssh-host=HOST                     SSH host" << std::endl;
    std::cout << "  --ssh-user=USER                     SSH user" << std::endl;
    std::cout << "  --ssh-port=PORT                     SSH port" << std::endl;
    std::cout << "  --ignore=name [--ignore=name]       ignore these files on copy" << std::endl;
}
