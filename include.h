/*
 * include.h
 *
 *  Created on: 2014/03/12
 *      Author: fernancoder
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <stdlib.h> 
#include <string.h> 
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <assert.h>

using namespace std;

#define UU __attribute__ ((unused))


#define CODE_bool_false 0xbc799737
#define CODE_bool_true 0x997275b5
#define CODE_vector 0x1cb5c415
#define CODE_error 0xc4b9f9bb
#define CODE_null 0x56730bcc
#define CODE_input_peer_empty 0x7f3b18ea
#define CODE_input_peer_self 0x7da07ec9
#define CODE_input_peer_contact 0x1023dbe8
#define CODE_input_peer_foreign 0x9b447325
#define CODE_input_peer_chat 0x179be863
#define CODE_input_user_empty 0xb98886cf
#define CODE_input_user_self 0xf7c1b13f
#define CODE_input_user_contact 0x86e94f65
#define CODE_input_user_foreign 0x655e74ff
#define CODE_input_phone_contact 0xf392b7f4
#define CODE_input_file 0xf52ff27f
#define CODE_input_media_empty 0x9664f57f
#define CODE_input_media_uploaded_photo 0x2dc53a7d
#define CODE_input_media_photo 0x8f2ab2ec
#define CODE_input_media_geo_point 0xf9c44144
#define CODE_input_media_contact 0xa6e45987
#define CODE_input_media_uploaded_video 0x4847d92a
#define CODE_input_media_uploaded_thumb_video 0xe628a145
#define CODE_input_media_video 0x7f023ae6
#define CODE_input_chat_photo_empty 0x1ca48f57
#define CODE_input_chat_uploaded_photo 0x94254732
#define CODE_input_chat_photo 0xb2e1bf08
#define CODE_input_geo_point_empty 0xe4c123d6
#define CODE_input_geo_point 0xf3b7acc9
#define CODE_input_photo_empty 0x1cd7bf0d
#define CODE_input_photo 0xfb95c6c4
#define CODE_input_video_empty 0x5508ec75
#define CODE_input_video 0xee579652
#define CODE_input_file_location 0x14637196
#define CODE_input_video_file_location 0x3d0364ec
#define CODE_input_photo_crop_auto 0xade6b004
#define CODE_input_photo_crop 0xd9915325
#define CODE_input_app_event 0x770656a8
#define CODE_peer_user 0x9db1bc6d
#define CODE_peer_chat 0xbad0e5bb
#define CODE_storage_file_unknown 0xaa963b05
#define CODE_storage_file_jpeg 0x7efe0e
#define CODE_storage_file_gif 0xcae1aadf
#define CODE_storage_file_png 0xa4f63c0
#define CODE_storage_file_mp3 0x528a0677
#define CODE_storage_file_mov 0x4b09ebbc
#define CODE_storage_file_partial 0x40bc6f52
#define CODE_storage_file_mp4 0xb3cea0e4
#define CODE_storage_file_webp 0x1081464c
#define CODE_file_location_unavailable 0x7c596b46
#define CODE_file_location 0x53d69076
#define CODE_user_empty 0x200250ba
#define CODE_user_self 0x720535ec
#define CODE_user_contact 0xf2fb8319
#define CODE_user_request 0x22e8ceb0
#define CODE_user_foreign 0x5214c89d
#define CODE_user_deleted 0xb29ad7cc
#define CODE_user_profile_photo_empty 0x4f11bae1
#define CODE_user_profile_photo 0xd559d8c8
#define CODE_user_status_empty 0x9d05049
#define CODE_user_status_online 0xedb93949
#define CODE_user_status_offline 0x8c703f
#define CODE_chat_empty 0x9ba2d800
#define CODE_chat 0x6e9c9bc7
#define CODE_chat_forbidden 0xfb0ccc41
#define CODE_chat_full 0x630e61be
#define CODE_chat_participant 0xc8d7493e
#define CODE_chat_participants_forbidden 0xfd2bb8a
#define CODE_chat_participants 0x7841b415
#define CODE_chat_photo_empty 0x37c1011c
#define CODE_chat_photo 0x6153276a
#define CODE_message_empty 0x83e5de54
#define CODE_message 0x22eb6aba
#define CODE_message_forwarded 0x5f46804
#define CODE_message_service 0x9f8d60bb
#define CODE_message_media_empty 0x3ded6320
#define CODE_message_media_photo 0xc8c45a2a
#define CODE_message_media_video 0xa2d24290
#define CODE_message_media_geo 0x56e0d474
#define CODE_message_media_contact 0x5e7d2f39
#define CODE_message_media_unsupported 0x29632a36
#define CODE_message_action_empty 0xb6aef7b0
#define CODE_message_action_chat_create 0xa6638b9a
#define CODE_message_action_chat_edit_title 0xb5a1ce5a
#define CODE_message_action_chat_edit_photo 0x7fcb13a8
#define CODE_message_action_chat_delete_photo 0x95e3fbef
#define CODE_message_action_chat_add_user 0x5e3cfc4b
#define CODE_message_action_chat_delete_user 0xb2ae9b0c
#define CODE_dialog 0x214a8cdf
#define CODE_photo_empty 0x2331b22d
#define CODE_photo 0x22b56751
#define CODE_photo_size_empty 0xe17e23c
#define CODE_photo_size 0x77bfb61b
#define CODE_photo_cached_size 0xe9a734fa
#define CODE_video_empty 0xc10658a8
#define CODE_video 0x5a04a49f
#define CODE_geo_point_empty 0x1117dd5f
#define CODE_geo_point 0x2049d70c
#define CODE_auth_checked_phone 0xe300cc3b
#define CODE_auth_sent_code 0x2215bcbd
#define CODE_auth_authorization 0xf6b673a4
#define CODE_auth_exported_authorization 0xdf969c2d
#define CODE_input_notify_peer 0xb8bc5b0c
#define CODE_input_notify_users 0x193b4417
#define CODE_input_notify_chats 0x4a95e84e
#define CODE_input_notify_all 0xa429b886
#define CODE_input_peer_notify_events_empty 0xf03064d8
#define CODE_input_peer_notify_events_all 0xe86a2c74
#define CODE_input_peer_notify_settings 0x46a2ce98
#define CODE_peer_notify_events_empty 0xadd53cb3
#define CODE_peer_notify_events_all 0x6d1ded88
#define CODE_peer_notify_settings_empty 0x70a68512
#define CODE_peer_notify_settings 0x8d5e11ee
#define CODE_wall_paper 0xccb03657
#define CODE_user_full 0x771095da
#define CODE_contact 0xf911c994
#define CODE_imported_contact 0xd0028438
#define CODE_contact_blocked 0x561bc879
#define CODE_contact_found 0xea879f95
#define CODE_contact_suggested 0x3de191a1
#define CODE_contact_status 0xaa77b873
#define CODE_chat_located 0x3631cf4c
#define CODE_contacts_foreign_link_unknown 0x133421f8
#define CODE_contacts_foreign_link_requested 0xa7801f47
#define CODE_contacts_foreign_link_mutual 0x1bea8ce1
#define CODE_contacts_my_link_empty 0xd22a1c60
#define CODE_contacts_my_link_requested 0x6c69efee
#define CODE_contacts_my_link_contact 0xc240ebd9
#define CODE_contacts_link 0xeccea3f5
#define CODE_contacts_contacts 0x6f8b8cb2
#define CODE_contacts_contacts_not_modified 0xb74ba9d2
#define CODE_contacts_imported_contacts 0xd1cd0a4c
#define CODE_contacts_blocked 0x1c138d15
#define CODE_contacts_blocked_slice 0x900802a1
#define CODE_contacts_found 0x566000e
#define CODE_contacts_suggested 0x5649dcc5
#define CODE_messages_dialogs 0x15ba6c40
#define CODE_messages_dialogs_slice 0x71e094f3
#define CODE_messages_messages 0x8c718e87
#define CODE_messages_messages_slice 0xb446ae3
#define CODE_messages_message_empty 0x3f4e0648
#define CODE_messages_message 0xff90c417
#define CODE_messages_stated_messages 0x969478bb
#define CODE_messages_stated_message 0xd07ae726
#define CODE_messages_sent_message 0xd1f4d35c
#define CODE_messages_chat 0x40e9002a
#define CODE_messages_chats 0x8150cbd8
#define CODE_messages_chat_full 0xe5d7d19c
#define CODE_messages_affected_history 0xb7de36f2
#define CODE_input_messages_filter_empty 0x57e2f66c
#define CODE_input_messages_filter_photos 0x9609a51c
#define CODE_input_messages_filter_video 0x9fc00e65
#define CODE_input_messages_filter_photo_video 0x56e9f0e4
#define CODE_update_new_message 0x13abdb3
#define CODE_update_message_i_d 0x4e90bfd6
#define CODE_update_read_messages 0xc6649e31
#define CODE_update_delete_messages 0xa92bfe26
#define CODE_update_restore_messages 0xd15de04d
#define CODE_update_user_typing 0x6baa8508
#define CODE_update_chat_user_typing 0x3c46cfe6
#define CODE_update_chat_participants 0x7761198
#define CODE_update_user_status 0x1bfbd823
#define CODE_update_user_name 0xda22d9ad
#define CODE_update_user_photo 0x95313b0c
#define CODE_update_contact_registered 0x2575bbb9
#define CODE_update_contact_link 0x51a48a9a
#define CODE_update_activation 0x6f690963
#define CODE_update_new_authorization 0x8f06529a
#define CODE_updates_state 0xa56c2a3e
#define CODE_updates_difference_empty 0x5d75a138
#define CODE_updates_difference 0xf49ca0
#define CODE_updates_difference_slice 0xa8fb1981
#define CODE_updates_too_long 0xe317af7e
#define CODE_update_short_message 0xd3f45784
#define CODE_update_short_chat_message 0x2b2fbd4e
#define CODE_update_short 0x78d4dec1
#define CODE_updates_combined 0x725b04c3
#define CODE_updates 0x74ae4240
#define CODE_photos_photos 0x8dca6aa5
#define CODE_photos_photos_slice 0x15051f54
#define CODE_photos_photo 0x20212ca8
#define CODE_upload_file 0x96a18d5
#define CODE_dc_option 0x2ec2a43c
#define CODE_config 0x232d5905
#define CODE_nearest_dc 0x8e1a1775
#define CODE_help_app_update 0x8987f311
#define CODE_help_no_app_update 0xc45a6536
#define CODE_help_invite_text 0x18cb9f78
#define CODE_messages_stated_messages_links 0x3e74f5c6
#define CODE_messages_stated_message_link 0xa9af2881
#define CODE_messages_sent_message_link 0xe9db4a3f
#define CODE_input_geo_chat 0x74d456fa
#define CODE_input_notify_geo_chat_peer 0x4d8ddec8
#define CODE_geo_chat 0x75eaea5a
#define CODE_geo_chat_message_empty 0x60311a9b
#define CODE_geo_chat_message 0x4505f8e1
#define CODE_geo_chat_message_service 0xd34fa24e
#define CODE_geochats_stated_message 0x17b1578b
#define CODE_geochats_located 0x48feb267
#define CODE_geochats_messages 0xd1526db1
#define CODE_geochats_messages_slice 0xbc5863e8
#define CODE_message_action_geo_chat_create 0x6f038ebc
#define CODE_message_action_geo_chat_checkin 0xc7d53de
#define CODE_update_new_geo_chat_message 0x5a68e3f7
#define CODE_wall_paper_solid 0x63117f24
#define CODE_update_new_encrypted_message 0x12bcbd9a
#define CODE_update_encrypted_chat_typing 0x1710f156
#define CODE_update_encryption 0xb4a2e88d
#define CODE_update_encrypted_messages_read 0x38fe25b7
#define CODE_encrypted_chat_empty 0xab7ec0a0
#define CODE_encrypted_chat_waiting 0x3bf703dc
#define CODE_encrypted_chat_requested 0xc878527e
#define CODE_encrypted_chat 0xfa56ce36
#define CODE_encrypted_chat_discarded 0x13d6dd27
#define CODE_input_encrypted_chat 0xf141b5e1
#define CODE_encrypted_file_empty 0xc21f497e
#define CODE_encrypted_file 0x4a70994c
#define CODE_input_encrypted_file_empty 0x1837c364
#define CODE_input_encrypted_file_uploaded 0x64bd0306
#define CODE_input_encrypted_file 0x5a17b5e5
#define CODE_input_encrypted_file_location 0xf5235d55
#define CODE_encrypted_message 0xed18c118
#define CODE_encrypted_message_service 0x23734b06
#define CODE_decrypted_message_layer 0x99a438cf
#define CODE_decrypted_message 0x1f814f1f
#define CODE_decrypted_message_service 0xaa48327d
#define CODE_decrypted_message_media_empty 0x89f5c4a
#define CODE_decrypted_message_media_photo 0x32798a8c
#define CODE_decrypted_message_media_video 0x4cee6ef3
#define CODE_decrypted_message_media_geo_point 0x35480a59
#define CODE_decrypted_message_media_contact 0x588a0a97
#define CODE_decrypted_message_action_set_message_t_t_l 0xa1733aec
#define CODE_messages_dh_config_not_modified 0xc0e24635
#define CODE_messages_dh_config 0x2c221edd
#define CODE_messages_sent_encrypted_message 0x560f8935
#define CODE_messages_sent_encrypted_file 0x9493ff32
#define CODE_input_file_big 0xfa4f0bb5
#define CODE_input_encrypted_file_big_uploaded 0x2dc173c8
#define CODE_update_chat_participant_add 0x3a0eeb22
#define CODE_update_chat_participant_delete 0x6e5f8c22
#define CODE_update_dc_options 0x8e5e9873
#define CODE_input_media_uploaded_audio 0x61a6d436
#define CODE_input_media_audio 0x89938781
#define CODE_input_media_uploaded_document 0x34e794bd
#define CODE_input_media_uploaded_thumb_document 0x3e46de5d
#define CODE_input_media_document 0xd184e841
#define CODE_message_media_document 0x2fda2204
#define CODE_message_media_audio 0xc6b68300
#define CODE_input_audio_empty 0xd95adc84
#define CODE_input_audio 0x77d440ff
#define CODE_input_document_empty 0x72f0eaae
#define CODE_input_document 0x18798952
#define CODE_input_audio_file_location 0x74dc404d
#define CODE_input_document_file_location 0x4e45abe9
#define CODE_decrypted_message_media_document 0xb095434b
#define CODE_decrypted_message_media_audio 0x6080758f
#define CODE_audio_empty 0x586988d8
#define CODE_audio 0x427425e7
#define CODE_document_empty 0x36f8c871
#define CODE_document 0x9efc6326
#define CODE_invoke_after_msg 0xcb9f372d
#define CODE_invoke_after_msgs 0x3dc4b4f0
#define CODE_invoke_with_layer1 0x53835315
#define CODE_auth_check_phone 0x6fe51dfb
#define CODE_auth_send_code 0x768d5f4d
#define CODE_auth_send_call 0x3c51564
#define CODE_auth_sign_up 0x1b067634
#define CODE_auth_sign_in 0xbcd51581
#define CODE_auth_log_out 0x5717da40
#define CODE_auth_reset_authorizations 0x9fab0d1a
#define CODE_auth_send_invites 0x771c1d97
#define CODE_auth_export_authorization 0xe5bfffcd
#define CODE_auth_import_authorization 0xe3ef9613
#define CODE_account_register_device 0x446c712c
#define CODE_account_unregister_device 0x65c55b40
#define CODE_account_update_notify_settings 0x84be5b93
#define CODE_account_get_notify_settings 0x12b3ad31
#define CODE_account_reset_notify_settings 0xdb7e1747
#define CODE_account_update_profile 0xf0888d68
#define CODE_account_update_status 0x6628562c
#define CODE_account_get_wall_papers 0xc04cfac2
#define CODE_users_get_users 0xd91a548
#define CODE_users_get_full_user 0xca30a5b1
#define CODE_contacts_get_statuses 0xc4a353ee
#define CODE_contacts_get_contacts 0x22c6aa08
#define CODE_contacts_import_contacts 0xda30b32d
#define CODE_contacts_search 0x11f812d8
#define CODE_contacts_get_suggested 0xcd773428
#define CODE_contacts_delete_contact 0x8e953744
#define CODE_contacts_delete_contacts 0x59ab389e
#define CODE_contacts_block 0x332b49fc
#define CODE_contacts_unblock 0xe54100bd
#define CODE_contacts_get_blocked 0xf57c350f
#define CODE_messages_get_messages 0x4222fa74
#define CODE_messages_get_dialogs 0xeccf1df6
#define CODE_messages_get_history 0x92a1df2f
#define CODE_messages_search 0x7e9f2ab
#define CODE_messages_read_history 0xb04f2510
#define CODE_messages_delete_history 0xf4f8fb61
#define CODE_messages_delete_messages 0x14f2dd0a
#define CODE_messages_restore_messages 0x395f9d7e
#define CODE_messages_received_messages 0x28abcb68
#define CODE_messages_set_typing 0x719839e9
#define CODE_messages_send_message 0x4cde0aab
#define CODE_messages_send_media 0xa3c85d76
#define CODE_messages_forward_messages 0x514cd10f
#define CODE_messages_get_chats 0x3c6aa187
#define CODE_messages_get_full_chat 0x3b831c66
#define CODE_messages_edit_chat_title 0xb4bc68b5
#define CODE_messages_edit_chat_photo 0xd881821d
#define CODE_messages_add_chat_user 0x2ee9ee9e
#define CODE_messages_delete_chat_user 0xc3c5cd23
#define CODE_messages_create_chat 0x419d9aee
#define CODE_updates_get_state 0xedd4882a
#define CODE_updates_get_difference 0xa041495
#define CODE_photos_update_profile_photo 0xeef579a0
#define CODE_photos_upload_profile_photo 0xd50f9c88
#define CODE_upload_save_file_part 0xb304a621
#define CODE_upload_get_file 0xe3a6cfb5
#define CODE_help_get_config 0xc4f9186b
#define CODE_help_get_nearest_dc 0x1fb33026
#define CODE_help_get_app_update 0xc812ac7e
#define CODE_help_save_app_log 0x6f02f748
#define CODE_help_get_invite_text 0xa4a95186
#define CODE_photos_get_user_photos 0xb7ee553c
#define CODE_invoke_with_layer2 0x289dd1f6
#define CODE_messages_forward_message 0x3f3f4f2
#define CODE_messages_send_broadcast 0x41bb0972
#define CODE_invoke_with_layer3 0xb7475268
#define CODE_geochats_get_located 0x7f192d8f
#define CODE_geochats_get_recents 0xe1427e6f
#define CODE_geochats_checkin 0x55b3e8fb
#define CODE_geochats_get_full_chat 0x6722dd6f
#define CODE_geochats_edit_chat_title 0x4c8e2273
#define CODE_geochats_edit_chat_photo 0x35d81a95
#define CODE_geochats_search 0xcfcdc44d
#define CODE_geochats_get_history 0xb53f7a68
#define CODE_geochats_set_typing 0x8b8a729
#define CODE_geochats_send_message 0x61b0044
#define CODE_geochats_send_media 0xb8f0deff
#define CODE_geochats_create_geo_chat 0xe092e16
#define CODE_invoke_with_layer4 0xdea0d430
#define CODE_invoke_with_layer5 0x417a57ae
#define CODE_invoke_with_layer6 0x3a64d54d
#define CODE_invoke_with_layer7 0xa5be56d3
#define CODE_messages_get_dh_config 0x26cf8950
#define CODE_messages_request_encryption 0xf64daf43
#define CODE_messages_accept_encryption 0x3dbc0415
#define CODE_messages_discard_encryption 0xedd923c5
#define CODE_messages_set_encrypted_typing 0x791451ed
#define CODE_messages_read_encrypted_history 0x7f4b690a
#define CODE_messages_send_encrypted 0xa9776773
#define CODE_messages_send_encrypted_file 0x9a901b66
#define CODE_messages_send_encrypted_service 0x32d439a4
#define CODE_messages_received_queue 0x55a5bb66
#define CODE_invoke_with_layer8 0xe9abd9fd
#define CODE_upload_save_big_file_part 0xde7b673d
#define CODE_init_connection 0x69796de9
#define CODE_invoke_with_layer9 0x76715a63
#define CODE_invoke_with_layer10 0x39620c41
#define CODE_invoke_with_layer11 0xa6b88fdf

//*******************************************//

#define	CODE_req_pq			0x60469778
#define CODE_resPQ			0x05162463
#define CODE_req_DH_params		0xd712e4be
#define CODE_p_q_inner_data		0x83c95aec
#define CODE_server_DH_inner_data	0xb5890dba
#define CODE_server_DH_params_fail	0x79cb045d
#define CODE_server_DH_params_ok	0xd0e8075c
#define CODE_set_client_DH_params	0xf5045f1f
#define CODE_client_DH_inner_data	0x6643b654
#define CODE_dh_gen_ok			0x3bcbf734
#define CODE_dh_gen_retry		0x46dc1fb9
#define CODE_dh_gen_fail		0xa69dae02 

/* service messages */
#define CODE_rpc_result			0xf35c6d01
#define CODE_rpc_error			0x2144ca19
#define CODE_msg_container		0x73f1f8dc
#define CODE_msg_copy			0xe06046b2
#define CODE_msgs_ack			0x62d6b459
#define CODE_bad_msg_notification	0xa7eff811
#define	CODE_bad_server_salt		0xedab447b
#define CODE_msgs_state_req		0xda69fb52
#define CODE_msgs_state_info		0x04deb57d
#define CODE_msgs_all_info		0x8cc0d131
#define CODE_new_session_created	0x9ec20908
#define CODE_msg_resend_req		0x7d861a08
#define CODE_ping			0x7abe77ec
#define CODE_pong			0x347773c5
#define CODE_destroy_session		0xe7512126
#define CODE_destroy_session_ok		0xe22045fc
#define CODE_destroy_session_none      	0x62d350c9
#define CODE_destroy_sessions		0x9a6face8
#define CODE_destroy_sessions_res	0xa8164668
#define	CODE_get_future_salts		0xb921bd04
#define	CODE_future_salt		0x0949d9dc
#define	CODE_future_salts		0xae500895
#define	CODE_rpc_drop_answer		0x58e4a740
#define CODE_rpc_answer_unknown		0x5e2ad36e
#define CODE_rpc_answer_dropped_running	0xcd78e586
#define CODE_rpc_answer_dropped		0xa43ad8b7
#define	CODE_msg_detailed_info		0x276d3ec6
#define	CODE_msg_new_detailed_info	0x809db6df
#define CODE_ping_delay_disconnect	0xf3427b8c
#define CODE_gzip_packed 0x3072cfa1

#define CODE_input_peer_notify_settings_old 0x3cf4b1be
#define CODE_peer_notify_settings_old 0xddbcd4a5
#define CODE_user_profile_photo_old 0x990d1493

#define CODE_msg_new_detailed_info 0x809db6df

#define CODE_msg_detailed_info 0x276d3ec6
/* not really a limit, for struct encrypted_message only */
// #define MAX_MESSAGE_INTS	16384
#define MAX_MESSAGE_INTS	1048576
#define MAX_PROTO_MESSAGE_INTS	1048576

#define PACKET_BUFFER_SIZE	(16384 * 100 + 16) // temp fix
#define MAX_RESPONSE_SIZE        (1L << 24)

#define sha1 SHA1
