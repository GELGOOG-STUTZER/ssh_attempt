#define LIBSSH_STATIC 1                                                             // этот define нужен для линковки (ОБЯЗАТЕЛЬНО ДОЛЖЕН СТОЯТЬ ПЕРЕД include libssh)
#include <stdlib.h>
#include <stdio.h>
#include <libssh/libssh.h>

int main() {
	ssh_session my_ssh_session;
	int rc;

	my_ssh_session = ssh_new();                                                 // создаем ssh сессию
	if (my_ssh_session == NULL)                                                 // проверяем, что все нормально 
		exit(-1);                                                           //
	
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");             // устанавливаем опции (см. https://api.libssh.org/stable/group__libssh__session.html#ga7a801b85800baa3f4e16f5b47db0a73d)
	
	rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(my_ssh_session));
		exit(-1);
	}
	
	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);                                                   // закрываем ssh сессию (ОБЯЗАТЕЛЬНО)
}
