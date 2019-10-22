/*! MS lookup fake API for testing purposes. */

struct osmo_mslookup_fake_response {
	struct timeval time_to_reply;
	struct osmo_mslookup_id for_id;
	const char *for_service;
	struct osmo_mslookup_result result;
	bool sent;
};

struct osmo_mslookup_client_method *osmo_mslookup_client_add_fake(struct osmo_mslookup_client *client,
								  struct osmo_mslookup_fake_response *responses,
								  size_t responses_len);
