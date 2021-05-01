#define LIBSSH_STATIC 1                                                             // этот define нужен для линковки (ОБЯЗАТЕЛЬНО ДОЛЖЕН СТОЯТЬ ПЕРЕД include libssh)
#include <stdlib.h>
#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <fstream>
#include <errno.h>
#include <string.h>

int sftp_transfer(ssh_session session, std::string path) {
	sftp_session sftp;
	int rc;
	char* filepath;
	filepath = &path[0];
	sftp = sftp_new(session);
	if (sftp == NULL) {
		fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
		return SSH_ERROR;
	}
	rc = sftp_init(sftp);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error initializing SFTP session: code %d.\n", sftp_get_error(sftp));
		sftp_free(sftp);
		return rc;
	}

	int access_type = O_WRONLY | O_CREAT | O_TRUNC;
	sftp_file file;
	file = sftp_open(sftp, filepath, access_type, S_IRWXU);
	if (file == NULL) {
	       	fprintf(stderr, "Can't open file for writing: %s\n", ssh_get_error(session));
		return SSH_ERROR;
	}

	std::ifstream fin("meme_example2.mp4", std::ios::binary);
	size_t nread;
	
	while (fin) {
	    char buffer[10240];
	    fin.read(buffer, sizeof(buffer));
	    if (fin.gcount() > 0) {
		    ssize_t nwritten = sftp_write(file, buffer, fin.gcount());
		    if (nwritten != fin.gcount()) {
			    fprintf(stderr, "Can't write data to file: %s\n", ssh_get_error(session));
			    sftp_close(file);
			    return 1;
		    }
	    }
	}

	sftp_close(file);
	sftp_free(sftp);
	return 0;
}

int verify_knownhost(ssh_session session) {
	enum ssh_known_hosts_e state;
	char *hexa;
	unsigned char *hash = NULL;
	size_t hlen;
	char *p;
	int cmp;
	int rc;
	char buf[10];
	state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */

            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
            fprintf(stderr, "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);

            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);

            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");

            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */

        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }

            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }

            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }

            break;
        case SSH_KNOWN_HOSTS_ERROR:
            fprintf(stderr, "Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }

    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int authenticate_pubkey(ssh_session session) {
	int rc;
	rc = ssh_userauth_publickey_auto(session, NULL, NULL);
	if (rc == SSH_AUTH_ERROR) {
		fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(session));
		return SSH_AUTH_ERROR;
	}
	return 0;
}

int main() {
	ssh_session my_ssh_session;
	int rc;
	std::string filepath = "meme_example2.mp4"; // может кидать в определенную директорию (например DATA/meme_example2.jpg)

	my_ssh_session = ssh_new();                                                 // создаем ssh сессию
	if (my_ssh_session == NULL)                                                 // проверяем, что все нормально 
		exit(-1);                                                           //
	
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "antonpc@192.168.1.171");             // устанавливаем опции (см. https://api.libssh.org/stable/group__libssh__session.html#ga7a801b85800baa3f4e16f5b47db0a73d)
	// КАК ПИШЕТСЯ АДРЕС К КОТОРОМУ ПОДКЛЮЧАТЬСЯ (имя учетки на компе к которому подключаешься)@(айпишник) пример см.выше
	rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to host: %s\n", ssh_get_error(my_ssh_session));
		exit(-1);
	}

	rc = verify_knownhost(my_ssh_session);
	if (rc != 0) {
		fprintf(stderr, "Error verifying host\n");
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	rc = authenticate_pubkey(my_ssh_session);
	if (rc != 0) {
                fprintf(stderr, "Error during authentification\n");
                ssh_disconnect(my_ssh_session);
                ssh_free(my_ssh_session);
                exit(-1);
        }


	
	int transfer_status;

	transfer_status = sftp_transfer(my_ssh_session, filepath); // здесь идет передача файла см. соответствующую функцию
	if (transfer_status != 0) {
                fprintf(stderr, "Error file transfer\n");
                exit(-1);
        }

	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);                                                   // закрываем ssh сессию (ОБЯЗАТЕЛЬНО)
}
