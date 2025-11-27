

.PHONY: all tests
all: tests

tests: run_test_client_list_mode
	$(MAKE) -C ./state_file/ tests

# client list mode tests
run_test_client_list_mode: test_client_list_mode
	./test_client_list_mode

TEST_CLIENT_LIST_MODE_OBJECT := \
	test_client_list_mode.c \
	../src/client_list.c \
	../src/conf.c \
	../src/debug.c \
	../src/safe.c \
	../src/tc.c \
	../src/util.c

test_client_list_mode: $(TEST_CLIENT_LIST_MODE_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o test_client_list_mode $+ $(LDLIBS)
