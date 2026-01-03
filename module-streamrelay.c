#define MODULE_LOG_PREFIX "relay"

#include "globals.h"

#ifdef MODULE_STREAMRELAY

#if !STATIC_LIBDVBCSA
#include <dlfcn.h>
#endif
#include "module-streamrelay.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-config.h"
#include "oscam-net.h"
#include "oscam-string.h"
#include "oscam-time.h"

#define STREAM_UNDEFINED 0x00
#define STREAM_VIDEO     0x01
#define STREAM_AUDIO     0x02
#define STREAM_SUBTITLE  0x03
#define STREAM_TELETEXT  0x04

extern int32_t exit_oscam;

typedef struct
{
	int32_t connfd;
	int32_t connid;
	char stream_host[256];
} stream_client_conn_data;

char *stream_source_auth = NULL;
uint32_t cluster_size = 50;
bool has_dvbcsa_ecm = 0, is_dvbcsa_static = 1;
#if DVBCSA_KEY_ECM
static uint8_t (*dvbcsa_get_ecm_table_fn)(void) = NULL;
#endif

static uint8_t stream_server_mutex_init = 0;
static pthread_mutex_t stream_server_mutex;
static int32_t glistenfd, mod_idx, gconncount = 0, gconnfd[STREAM_SERVER_MAX_CONNECTIONS], stream_resptime[STREAM_SERVER_MAX_CONNECTIONS];
static char ecm_src[STREAM_SERVER_MAX_CONNECTIONS][9];
static IN_ADDR_T client_ip[STREAM_SERVER_MAX_CONNECTIONS], stream_host_ip[STREAM_SERVER_MAX_CONNECTIONS];
static in_port_t client_port[STREAM_SERVER_MAX_CONNECTIONS];
struct s_client *streamrelay_client[STREAM_SERVER_MAX_CONNECTIONS];

static pthread_mutex_t fixed_key_srvid_mutex;
static uint16_t stream_cur_srvid[STREAM_SERVER_MAX_CONNECTIONS];
static stream_client_key_data key_data[STREAM_SERVER_MAX_CONNECTIONS];
#if DVBCSA_KEY_ECM
static uint16_t last_srvid[STREAM_SERVER_MAX_CONNECTIONS];
#endif

#ifdef MODULE_RADEGAST
static int32_t gRadegastFd = 0;

static bool connect_to_radegast(void)
{
	struct SOCKADDR cservaddr;

	if (gRadegastFd == 0)
		gRadegastFd = socket(DEFAULT_AF, SOCK_STREAM, 0);

	if (gRadegastFd < 0)
	{
		gRadegastFd = 0;
		return false;
	}

	int32_t flags = fcntl(gRadegastFd, F_GETFL);
	fcntl(gRadegastFd, F_SETFL, flags | O_NONBLOCK);

	bzero(&cservaddr, sizeof(cservaddr));
	SIN_GET_FAMILY(cservaddr) = DEFAULT_AF;
	SIN_GET_PORT(cservaddr) = htons(cfg.rad_port);
	SIN_GET_ADDR(cservaddr) = cfg.rad_srvip;

	if (connect(gRadegastFd, (struct sockaddr *)&cservaddr, sizeof(cservaddr)) == -1)
	{
		return false;
	}

	return true;
}

static void close_radegast_connection(void)
{
	close(gRadegastFd);
	gRadegastFd = 0;
}

static bool send_to_radegast(uint8_t* data, int len)
{
	if (send(gRadegastFd, data, len, 0) < 0)
	{
		cs_log("send_to_radegast: Send failure! (errno=%d %s)", errno, strerror(errno));
		return false;
	}
	return true;
}

static void radegast_client_ecm(stream_client_data *cdata)
{
	uint16_t section_length = SCT_LEN(cdata->ecm_data);
	uint8_t md5tmp[MD5_DIGEST_LENGTH];
	MD5(cdata->ecm_data, section_length, md5tmp);

	if (!memcmp(cdata->ecm_md5, md5tmp, MD5_DIGEST_LENGTH)) { return; }
	memcpy(cdata->ecm_md5, md5tmp, MD5_DIGEST_LENGTH);

	uint16_t packet_len;
	static uint8_t header_len = 2;
	static uint8_t payload_static_len = 12;

	if (gRadegastFd <= 0)
	{
		cs_log("HTTP stream including ECM header. Connecting radegast server to parse ECM data");
		connect_to_radegast();
	}

	packet_len = header_len + payload_static_len + section_length;
	uint8_t outgoing_data[packet_len];
	outgoing_data[0] = 1;
	outgoing_data[1] = payload_static_len + section_length;
	outgoing_data[2] = 10;  // caid
	outgoing_data[3] = 2;
	outgoing_data[4] = cdata->caid >> 8;
	outgoing_data[5] = cdata->caid & 0xFF;
	outgoing_data[6] = 9;   // srvid
	outgoing_data[7] = 4;
	outgoing_data[8] = cdata->srvid & 0xFF;
	outgoing_data[10] = cdata->srvid >> 8;
	outgoing_data[12] = 3;
	outgoing_data[13] = section_length;

	memcpy(outgoing_data + header_len + payload_static_len, cdata->ecm_data, section_length);

	if (!send_to_radegast(outgoing_data, packet_len))
	{
		close_radegast_connection();
		if (connect_to_radegast())
		{
			send_to_radegast(outgoing_data, packet_len);
		}
	}
}

void ParseEcmData(stream_client_data *cdata)
{
	uint8_t *data = cdata->ecm_data;
	uint16_t section_length = SCT_LEN(data);

	if (section_length < 11)
	{
		return;
	}

	cs_strncpy(ecm_src[cdata->connid], "radegast", sizeof(ecm_src[cdata->connid]));
	radegast_client_ecm(cdata);
}
#endif // MODULE_RADEGAST

static void write_cw(ECM_REQUEST *er, int32_t connid)
{
#if DVBCSA_KEY_ECM
	const uint8_t ecm = (cfg.stream_relay_ctab.ctnum == 0 && !select_csa_alt(er))
		? 0
		: get_ecm_mode(er);
#endif
	if (memcmp(er->cw, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0)
	{
		if (has_dvbcsa_ecm)
		{
			dvbcsa_bs_key_set(er->cw, key_data[connid].key[EVEN]);
		}
	}

	if (memcmp(er->cw + 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0)
	{
		if (has_dvbcsa_ecm)
		{
			dvbcsa_bs_key_set(er->cw + 8, key_data[connid].key[ODD]);
		}
	}
#if DVBCSA_KEY_ECM
	if (er->srvid != last_srvid[connid] && ecm != 0 && has_dvbcsa_ecm)
	{
		cs_log(dvbcsa_get_ecm_table_fn
			? "Using ecm_mode=0x%02X, libdvbcsa table 0x%02X"
			: "Using ecm_mode=0x%02X",
			ecm,
			dvbcsa_get_ecm_table_fn ? dvbcsa_get_ecm_table_fn() : 0);
		last_srvid[connid] = er->srvid;
	}
#endif
}

static void update_client_info(ECM_REQUEST *er, int32_t connid)
{
	time_t now;
	time(&now);
	if(cfg.stream_display_client)
	{
		streamrelay_client[connid]->ip = stream_host_ip[connid];
		streamrelay_client[connid]->port = cfg.stream_source_port;
	}
	else
	{
		streamrelay_client[connid]->ip = client_ip[connid];
		streamrelay_client[connid]->port = client_port[connid];
	}
	streamrelay_client[connid]->last_srvid = er->srvid;
	streamrelay_client[connid]->last_provid = er->prid;
	streamrelay_client[connid]->last_caid = er->caid;
#ifdef WEBIF
	snprintf(streamrelay_client[connid]->lastreader, sizeof(streamrelay_client[connid]->lastreader), "⇆ %.*s", 11, ecm_src[connid]);
#endif
	streamrelay_client[connid]->cwlastresptime = stream_resptime[connid];
	streamrelay_client[connid]->lastecm = now;
	streamrelay_client[connid]->lastswitch = streamrelay_client[connid]->last = time((time_t *)0); // reset idle-Time & last switch
}

bool stream_write_cw(ECM_REQUEST *er)
{
	int32_t i;
	if (er->rc == E_FOUND)
	{
		bool cw_written = false;
		//SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
		for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
		{
			if (stream_cur_srvid[i] == er->srvid)
			{
				write_cw(er, i);
				update_client_info(er, i);
				cw_written = true;
				// don't return as there might be more connections for the same channel (e.g. recordings)
			}
		}
		//SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);
		return cw_written;
	}
	return true;
}

static void SearchTsPackets(const uint8_t *buf, const uint32_t bufLength, uint16_t *packetSize, uint16_t *startOffset)
{
	uint32_t i;

	for (i = 0; i < bufLength; i++)
	{
		if (buf[i] == 0x47)
		{
			// if three packets align, probably safe to assume correct size
			if ((buf[i + 188] == 0x47) & (buf[i + 376] == 0x47))
			{
				(*packetSize) = 188;
				(*startOffset) = i;
				return;
			}
			else if ((buf[i + 204] == 0x47) & (buf[i + 408] == 0x47))
			{
				(*packetSize) = 204;
				(*startOffset) = i;
				return;
			}
			else if ((buf[i + 208] == 0x47) & (buf[i + 416] == 0x47))
			{
				(*packetSize) = 208;
				(*startOffset) = i;
				return;
			}
		}
	}

	(*packetSize) = 0;
	(*startOffset) = 0;
}

typedef void (*ts_data_callback)(stream_client_data *cdata);

static void ParseTsData(const uint8_t table_id, const uint8_t table_mask, const uint8_t min_table_length, int8_t *flag,
						uint8_t *data, const uint16_t data_length, uint16_t *data_pos, const int8_t payloadStart,
						const uint8_t *buf, const int32_t len, ts_data_callback func, stream_client_data *cdata)
{
	int32_t i;
	uint16_t offset = 0;
	bool found_start = 0;

	if (len < 1)
	{
		return;
	}

	if (*flag == 0 && !payloadStart)
	{
		return;
	}

	if (*flag == 0)
	{
		*data_pos = 0;
		offset = 1 + buf[0];
	}
	else if (payloadStart)
	{
		offset = 1;
	}

	if ((len - offset) < 1)
	{
		return;
	}

	const int32_t free_data_length = (data_length - *data_pos);
	const int32_t copySize = (len - offset) > free_data_length ? free_data_length : (len - offset);

	memcpy(data + *data_pos, buf + offset, copySize);
	*data_pos += copySize;

	for (i = 0; i < *data_pos; i++)
	{
		if ((data[i] & table_mask) == table_id)
		{
			if (i != 0)
			{
				if (*data_pos - i > i)
				{
					memmove(data, &data[i], *data_pos - i);
				}
				else
				{
					memcpy(data, &data[i], *data_pos - i);
				}

				*data_pos -= i;
			}
			found_start = 1;
			break;
		}
	}

	const uint16_t section_length = SCT_LEN(data);

	if (!found_start || (section_length > data_length) || (section_length < min_table_length))
	{
		*flag = 0;
		return;
	}

	if ((*data_pos < section_length) || (*data_pos < 3))
	{
		*flag = 2;
		return;
	}

	func(cdata);

	found_start = 0;
	for (i = section_length; i < *data_pos; i++)
	{
		if ((data[i] & table_mask) == table_id)
		{
			if (*data_pos - i > i)
			{
				memmove(data, &data[i], *data_pos - i);
			}
			else
			{
				memcpy(data, &data[i], *data_pos - i);
			}

			*data_pos -= i;
			found_start = 1;
			break;
		}
	}

	if (!found_start || (data_length < *data_pos + copySize + 1))
	{
		*data_pos = 0;
	}

	*flag = 1;
}

static void ParsePatData(stream_client_data *cdata)
{
	int32_t i;
	uint16_t srvid;
	for (i = 8; i + 7 < SCT_LEN(cdata->pat_data); i += 4)
	{
		srvid = b2i(2, cdata->pat_data + i);
		if (srvid == 0)
		{
			continue;
		}

		if (cdata->srvid == srvid)
		{
			cdata->pmt_pid = b2i(2, cdata->pat_data + i + 2) & 0x1FFF;
			cs_log_dbg(D_READER, "Stream client %i found pmt pid: 0x%04X (%i)",
						cdata->connid, cdata->pmt_pid, cdata->pmt_pid);
			break;
		}
	}
}

static void ParseDescriptors(const uint8_t *buffer, const uint16_t info_length, uint8_t *type)
{
	uint32_t i;
	uint8_t j, descriptor_length = 0;

	if (info_length < 1)
	{
		return;
	}

	for (i = 0; i + 1 < info_length; i += descriptor_length + 2)
	{
		descriptor_length = buffer[i + 1];
		switch (buffer[i]) // descriptor tag
		{
			case 0x05: // Registration descriptor
			{
				// "HDMV" format identifier is removed
				// Cam does not need to know about Blu-ray
				const char format_identifiers_audio[10][5] =
				{
					"AC-3", "BSSD", "dmat", "DRA1", "DTS1",
					"DTS2", "DTS3", "EAC3", "mlpa", "Opus",
				};
				for (j = 0; j < 10; j++)
				{
					if (memcmp(buffer + i + 2, format_identifiers_audio[j], 4) == 0)
					{
						*type = STREAM_AUDIO;
						break;
					}
				}
				break;
			}
			//case 0x09: // CA descriptor
			//{
			//	break;
			//}
			case 0x46: // VBI teletext descriptor (DVB)
			case 0x56: // teletext descriptor (DVB)
			{
				*type = STREAM_TELETEXT;
				break;
			}
			case 0x59: // subtitling descriptor (DVB)
			{
				*type = STREAM_SUBTITLE;
				break;
			}
			case 0x6A: // AC-3 descriptor (DVB)
			case 0x7A: // enhanced AC-3 descriptor (DVB)
			case 0x7B: // DTS descriptor (DVB)
			case 0x7C: // AAC descriptor (DVB)
			case 0x81: // AC-3 descriptor (ATSC)
			case 0xCC: // Enhanced AC-3 descriptor (ATSC)
			{
				*type = STREAM_AUDIO;
				break;
			}
			case 0x7F: // extension descriptor (DVB)
			{
				switch(buffer[i + 2]) // extension descriptor tag
				{
					case 0x0E: // DTS-HD descriptor (DVB)
					case 0x0F: // DTS Neural descriptor (DVB)
					case 0x15: // AC-4 descriptor (DVB)
						*type = STREAM_AUDIO;
						break;

					case 0x20: // TTML subtitling descriptor (DVB)
						*type = STREAM_SUBTITLE;
						break;

					default:
						*type = STREAM_UNDEFINED;
						break;
				}
				break;
			}
			default:
				break;
		}
	}
}

static void stream_parse_pmt_ca_descriptor(const uint8_t *data, const int32_t data_pos, const int32_t offset, const uint16_t info_length, stream_client_data *cdata)
{
	if (cdata->ecm_pid)
	{
		return;
	}

	// parse program descriptors (we are looking only for CA descriptor here)
	int32_t i;
	uint16_t caid;
	uint8_t descriptor_tag, descriptor_length = 0;

	for (i = offset; i + 1 < offset + info_length; i += descriptor_length + 2)
	{
		descriptor_tag = data[i + data_pos];
		descriptor_length = data[i + 1 + data_pos];
		if (descriptor_length < 1)
		{
			break;
		}

		if (i + 1 + descriptor_length >= offset + info_length)
		{
			break;
		}

		if (descriptor_tag == 0x09 && descriptor_length >= 4)
		{
			caid = b2i(2, data + i + 2 + data_pos);
			if (cfg.stream_relay_ctab.ctnum == 0 || chk_ctab_ex(caid, &cfg.stream_relay_ctab))
			{
				if (cdata->caid == NO_CAID_VALUE)
				{
					cdata->caid = caid;
				}

				if (cdata->caid != caid)
				{
					continue;
				}
				cdata->ecm_pid = b2i(2, data + i + 4 + data_pos) & 0x1FFF;
				cs_log_dbg(D_READER, "Stream client %i found ecm pid: 0x%04X (%i)",
							cdata->connid, cdata->ecm_pid, cdata->ecm_pid);
			}
			else if (cdata->blocked_caid == NO_CAID_VALUE)
			{
				// Remember first blocked CAID for error message
				cdata->blocked_caid = caid;
			}
		}
	}
}

static void ParsePmtData(stream_client_data *cdata)
{
	int32_t i;
	uint16_t program_info_length = 0, es_info_length = 0, elementary_pid;
	const uint16_t section_length = SCT_LEN(cdata->pmt_data);
	uint8_t offset = 0;

	cdata->ecm_pid = 0;
	cdata->pcr_pid = b2i(2, cdata->pmt_data + 8) & 0x1FFF;

	if (cdata->pcr_pid != 0x1FFF)
	{
		cs_log_dbg(D_READER, "Stream client %i found pcr pid: 0x%04X (%i)",
					cdata->connid, cdata->pcr_pid, cdata->pcr_pid);
	}
	program_info_length = b2i(2, cdata->pmt_data + 10) & 0xFFF;
	if (!program_info_length)
	{
		offset = 5;
		program_info_length = (b2i(2, cdata->pmt_data + 10 + offset) & 0xFFF);
	}
	if (12 + offset + program_info_length >= section_length) { return; }
	stream_parse_pmt_ca_descriptor(cdata->pmt_data, 0, 12 + offset, program_info_length, cdata);

	offset = offset == 5 ? 0 : program_info_length;
	for (i = 12 + offset; i + 4 <  section_length; i += 5 + es_info_length)
	{
		elementary_pid = b2i(2, cdata->pmt_data + i + 1) & 0x1FFF;
		es_info_length = b2i(2, cdata->pmt_data + i + 3) & 0xFFF;
		switch (cdata->pmt_data[i]) // stream type
		{
			case 0x01:
			case 0x02:
			case 0x10:
			case 0x1B:
			case 0x20:
			case 0x24:
			case 0x25:
			case 0x42:
			case 0xD1:
			case 0xEA:
			{
				cs_log_dbg(D_READER, "Stream client %i found video pid: 0x%04X (%i)",
							cdata->connid, elementary_pid, elementary_pid);
				stream_parse_pmt_ca_descriptor(cdata->pmt_data, i, 5, es_info_length, cdata);
				break;
			}
			case 0x03:
			case 0x04:
			case 0x0F:
			case 0x11:
			case 0x1C:
			case 0x2D:
			case 0x2E:
			case 0x81:
			{
				cs_log_dbg(D_READER, "Stream client %i found audio pid: 0x%04X (%i)",
							cdata->connid, elementary_pid, elementary_pid);
				break;
			}
			case 0x06:
			//case 0x81: // some ATSC AC-3 streams do not contain the AC-3 descriptor!
			case 0x87:
			{
				uint8_t type = STREAM_UNDEFINED;
				ParseDescriptors(cdata->pmt_data + i + 5, es_info_length, &type);
				if (type == STREAM_AUDIO)
				{
					cs_log_dbg(D_READER, "Stream client %i found audio pid: 0x%04X (%i)",
								cdata->connid, elementary_pid, elementary_pid);
				}
				else if (type == STREAM_TELETEXT)
				{
					cs_log_dbg(D_READER, "Stream client %i found teletext pid: 0x%04X (%i)",
								cdata->connid, elementary_pid, elementary_pid);
				}
				break;
			}
		}
	}
}

static void ParseTsPackets(stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize)
{
	uint8_t payloadStart;
	uint16_t pid, offset;
	uint32_t i, tsHeader;

	for (i = 0; i < bufLength; i += packetSize)
	{
		tsHeader = b2i(4, stream_buf + i);
		pid = (tsHeader & 0x1FFF00) >> 8;
		payloadStart = (tsHeader & 0x400000) >> 22;

		if (tsHeader & 0x20)
		{
			offset = 4 + stream_buf[i + 4] + 1;
		}
		else
		{
			offset = 4;
		}

		if (packetSize - offset < 1)
		{
			continue;
		}

		if (pid == 0x0000 && data->have_pat_data != 1) // Search the PAT for the PMT pid
		{
			ParseTsData(0x00, 0xFF, 16, &data->have_pat_data, data->pat_data, sizeof(data->pat_data),
						&data->pat_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParsePatData, data);
			continue;
		}

		if (pid == data->pmt_pid && data->have_pmt_data != 1) // Search the PMT for PCR, ECM, Video and Audio pids
		{
			ParseTsData(0x02, 0xFF, 21, &data->have_pmt_data, data->pmt_data, sizeof(data->pmt_data),
						&data->pmt_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParsePmtData, data);
			continue;
		}

		// We have bot PAT and PMT data - No need to search the rest of the packets
		if (data->have_pat_data == 1 && data->have_pmt_data == 1)
		{
			break;
		}
	}
}

static void decrypt(struct dvbcsa_bs_batch_s *tsbbatch, uint16_t fill[2], const uint8_t oddeven, const int32_t connid)
{
	if (fill[oddeven] > 0)
	{
#if 0
		uint16_t i;
		for(i = fill[oddeven]; i <= cluster_size; i++)
		{
			tsbbatch[i].data = NULL;
			tsbbatch[i].len = 0;
		}
#else
		tsbbatch[fill[oddeven]].data = NULL;
#endif
		cs_log_dbg(D_READER, "dvbcsa (%s), batch=%d", oddeven == ODD ? "odd" : "even", fill[oddeven]);

		fill[oddeven] = 0;

		dvbcsa_bs_decrypt(key_data[connid].key[oddeven], tsbbatch, 184);
	}
}
#define decrypt(a) decrypt(tsbbatch, fill, a, data->connid)

static void DescrambleTsPackets(stream_client_data *data, uint8_t *stream_buf, uint32_t bufLength, uint16_t packetSize, struct dvbcsa_bs_batch_s *tsbbatch)
{
	uint32_t i, tsHeader;
	uint16_t offset, fill[2] = {0,0};
	uint8_t oddeven = 0;
#ifdef MODULE_RADEGAST
	uint16_t pid;
	uint8_t payloadStart;
#endif

	for (i = 0; i < bufLength; i += packetSize)
	{
		tsHeader = b2i(4, stream_buf + i);
#ifdef MODULE_RADEGAST
		pid = (tsHeader & 0x1FFF00) >> 8;
		payloadStart = (tsHeader & 0x400000) >> 22;
#endif
		offset = (tsHeader & 0x20) ? 4 + stream_buf[i + 4] + 1 : 4;
		if (packetSize - offset < 1)
		{
			continue;
		}
#ifdef MODULE_RADEGAST
		if (data->ecm_pid && pid == data->ecm_pid) // Process the ECM data
		{
			// set to null pid
			stream_buf[i + 1] |= 0x1F;
			stream_buf[i + 2] = 0xFF;
			ParseTsData(0x80, 0xFE, 3, &data->have_ecm_data, data->ecm_data, sizeof(data->ecm_data),
						&data->ecm_data_pos, payloadStart, stream_buf + i + offset, packetSize - offset, ParseEcmData, data);
			continue;
		}
#endif // MODULE_RADEGAST
		if ((tsHeader & 0xC0) == 0)
		{
			continue;
		}

		stream_buf[i + 3] &= 0x3f; // consider it decrypted now
		oddeven = (tsHeader & 0xC0) == 0xC0 ? ODD: EVEN;
		decrypt(oddeven == ODD ? EVEN : ODD);
		tsbbatch[fill[oddeven]].data = &stream_buf[i + offset];
		tsbbatch[fill[oddeven]].len = packetSize - offset;
		fill[oddeven]++;

		if (fill[oddeven] > cluster_size - 1)
		{
			decrypt(oddeven);
		}
	}

	decrypt(oddeven);
}

static int32_t connect_to_stream(char *http_buf, int32_t http_buf_len, char *stream_path, char *stream_source_host, IN_ADDR_T *in_addr)
{
	struct SOCKADDR cservaddr;
	struct utsname buffer; uname(&buffer);

	int32_t streamfd = socket(DEFAULT_AF, SOCK_STREAM, 0), status;
	if (streamfd == -1) { return -1; }

	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if (setsockopt(streamfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv))
	{
		cs_log("ERROR: setsockopt() failed for SO_RCVTIMEO!");
		return -1;
	}

	bzero(&cservaddr, sizeof(cservaddr));
	SIN_GET_FAMILY(cservaddr) = DEFAULT_AF;
	SIN_GET_PORT(cservaddr) = htons(cfg.stream_source_port);
	cs_resolve(stream_source_host, in_addr, NULL, NULL);
	SIN_GET_ADDR(cservaddr) = *in_addr;

	if (connect(streamfd, (struct sockaddr *)&cservaddr, sizeof(cservaddr)) == -1)
	{
		cs_log("WARNING: Connect to stream source port %d failed.", cfg.stream_source_port);
		return -1;
	}

	snprintf(http_buf, http_buf_len,
			"GET %s HTTP/1.1\nHost: %s:%u\n"
			"User-Agent: Mozilla/5.0 (%s %s %s; rv:133.0) Gecko/20100101 Firefox/133.0\n"
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"
			"Accept-Language: en-US"
			"%s%s\n"
			"Connection: keep-alive\n\n",
			stream_path,
			cs_inet_ntoa(*in_addr),
			cfg.stream_source_port,
#if defined(__linux__)
			"X11;", buffer.sysname, buffer.machine,
#else
			"Windows NT 10.0;", "Win64;", "x64",
#endif
			(stream_source_auth) ? "\nAuthorization: Basic " : "",
			(stream_source_auth) ? stream_source_auth : "");

	status = send(streamfd, http_buf, cs_strlen(http_buf), 0);
	cs_log_dbg(D_CLIENT, "HTTP (send) (%i): %s", status, remove_newline_chars(http_buf));
	if ( status == -1) { return -1; }

	return streamfd;
}

static void stream_client_disconnect(stream_client_conn_data *conndata)
{
	int32_t i;

	SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
	stream_cur_srvid[conndata->connid] = NO_SRVID_VALUE;
#if DVBCSA_KEY_ECM
	last_srvid[conndata->connid] = NO_SRVID_VALUE;
#endif
	SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);

	SAFE_MUTEX_LOCK(&stream_server_mutex);
	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if (gconnfd[i] == conndata->connfd)
		{
			gconnfd[i] = -1;
			gconncount--;
		}
	}
	SAFE_MUTEX_UNLOCK(&stream_server_mutex);

	shutdown(conndata->connfd, 2);
	close(conndata->connfd);

	cs_log("Stream client %i disconnected. ip=%s port=%d", conndata->connid, cs_inet_ntoa(client_ip[conndata->connid]), client_port[conndata->connid]);

	if(streamrelay_client[conndata->connid] && !cfg.stream_reuse_client && !streamrelay_client[conndata->connid]->kill_started)
	{
		cs_disconnect_client(streamrelay_client[conndata->connid]);
		free_client(streamrelay_client[conndata->connid]);
	}

	NULLFREE(conndata);
}

static void streamrelay_auth_client(struct s_client *cl)
{
	int32_t ok = 0;
	struct s_auth *account;

	for(account = cfg.account; cfg.stream_relay_user && account; account = account->next)
	{
		if((ok = streq(cfg.stream_relay_user, account->usr)))
		{
			break;
		}
	}

	cs_auth_client(cl, ok ? account : (struct s_auth *)(-1), "streamrelay");
}

static void create_streamrelay_client(stream_client_conn_data *conndata)
{
	int32_t i, exists = 0;

	if (cfg.stream_reuse_client)
	{
		for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
		{
			if (streamrelay_client[i])
			{
				if (!streamrelay_client[i]->kill)
				{
					streamrelay_client[conndata->connid] = streamrelay_client[i];
					exists = 1;
					break;
				}
			}
		}
	}

	if (!exists)
		{ streamrelay_client[conndata->connid] = create_client(client_ip[conndata->connid]); }

	streamrelay_client[conndata->connid]->typ = 'c';
	streamrelay_client[conndata->connid]->module_idx = mod_idx;
	streamrelay_client[conndata->connid]->thread = pthread_self();
	streamrelay_client[conndata->connid]->ip = client_ip[conndata->connid];
	streamrelay_client[conndata->connid]->port = client_port[conndata->connid];
#ifdef WEBIF
	streamrelay_client[conndata->connid]->wihidden = cfg.stream_hide_client;
#endif
}

static void *stream_client_handler(void *arg)
{
	stream_client_conn_data *conndata = (stream_client_conn_data *)arg;
	stream_client_data *data;

	char *http_buf, stream_path[255], stream_path_copy[255];
	char *saveptr, *token, http_version[4], http_host[256];

	int8_t streamConnectErrorCount = 0, streamDataErrorCount = 0, streamReconnectCount = 0;
	int32_t bytesRead = 0, http_status_code = 0;
	int32_t i, clientStatus, streamStatus, streamfd, last_streamfd = 0;

	uint8_t *stream_buf;
	uint16_t packetCount = 0, packetSize = 0, startOffset = 0;
	uint32_t remainingDataPos, remainingDataLength, tmp_pids[4];
	uint8_t descrambling = 0;

	struct timeb start, end;

	const int32_t cur_dvb_buffer_size = DVB_BUFFER_SIZE_CSA;
	const int32_t cur_dvb_buffer_wait = DVB_BUFFER_WAIT_CSA;

	struct dvbcsa_bs_batch_s *tsbbatch;

	create_streamrelay_client(conndata);
	SAFE_SETSPECIFIC(getclient, streamrelay_client[conndata->connid]);
	set_thread_name(__func__);

	if(!streamrelay_client[conndata->connid]->init_done)
	{
		streamrelay_auth_client(streamrelay_client[conndata->connid]);
		streamrelay_client[conndata->connid]->init_done = 1;
	}

	cs_log("Stream client %i connected. ip=%s port=%d", conndata->connid, cs_inet_ntoa(client_ip[conndata->connid]), client_port[conndata->connid]);

	if (!cs_malloc(&http_buf, 1024))
	{
		stream_client_disconnect(conndata);
		return NULL;
	}

	if (!cs_malloc(&stream_buf, DVB_BUFFER_SIZE))
	{
		NULLFREE(http_buf);
		stream_client_disconnect(conndata);
		return NULL;
	}

	if (!cs_malloc(&data, sizeof(stream_client_data)))
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		stream_client_disconnect(conndata);
		return NULL;
	}

	clientStatus = recv(conndata->connfd, http_buf, 1024, 0);
	cs_log_dbg(D_CLIENT, "HTTP (recv) (%i): %s", clientStatus, remove_newline_chars(http_buf));

	if (clientStatus < 1)
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

	http_buf[1023] = '\0';
	if (sscanf(http_buf, "GET %254s HTTP/%3s Host: %255s ", stream_path, http_version, http_host) < 1)
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}
	else
	{
		//use stream_source_host variable from config as stream source host
		if(!cfg.stream_client_source_host)
		{
			cs_strncpy(conndata->stream_host, cfg.stream_source_host, sizeof(conndata->stream_host));
		}
		//use host from stream client http request as stream source host, if 'Host: host:port' header was send
		else if(strchr(http_host,':'))
		{
			char *hostline = cs_strdup((const char *)&http_host);
			cs_strncpy(conndata->stream_host, strsep(&hostline, ":"), sizeof(conndata->stream_host));
		}
		//use the IP address of the stream client itself as host for the stream source
		else
		{
			cs_strncpy(conndata->stream_host, cs_inet_ntoa(client_ip[conndata->connid]), sizeof(conndata->stream_host));
		}
	}

	cs_strncpy(stream_path_copy, stream_path, sizeof(stream_path));

	token = strtok_r(stream_path_copy, ":", &saveptr); // token 0
	for (i = 1; token != NULL && i < 7; i++) // tokens 1 to 6
	{
		token = strtok_r(NULL, ":", &saveptr);
		if (token == NULL)
		{
			break;
		}

		if (i >= 3) // We olny need token 3 (srvid), 4 (tsid), 5 (onid) and 6 (ens)
		{
			if (sscanf(token, "%x", &tmp_pids[i - 3]) != 1)
			{
				tmp_pids[i - 3] = 0;
			}
		}
	}

	data->srvid = tmp_pids[0] & 0xFFFF;
	data->tsid = tmp_pids[1] & 0xFFFF;
	data->onid = tmp_pids[2] & 0xFFFF;
	data->ens = tmp_pids[3];

	if (data->srvid == 0) // We didn't get a srvid - Exit
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

	key_data[conndata->connid].key[ODD]  = dvbcsa_bs_key_alloc();
	key_data[conndata->connid].key[EVEN] = dvbcsa_bs_key_alloc();

	if (!cs_malloc(&tsbbatch, (cluster_size + 1) * sizeof(struct dvbcsa_bs_batch_s)))
	{
		NULLFREE(http_buf);
		NULLFREE(stream_buf);
		NULLFREE(data);
		stream_client_disconnect(conndata);
		return NULL;
	}

	SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
	stream_cur_srvid[conndata->connid] = data->srvid;
	SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);

	cs_log("Stream client %i request. host=%s port=%d path=%s (%s)", conndata->connid, conndata->stream_host, cfg.stream_source_port, stream_path, !cfg.stream_client_source_host ? "config" : strchr(http_host,':') ? "http header" : "client ip");

	cs_log_dbg(D_READER, "Stream client %i received srvid: %04X tsid: %04X onid: %04X ens: %08X",
				conndata->connid, data->srvid, data->tsid, data->onid, data->ens);

	snprintf(http_buf, 1024,
			"HTTP/1.0 200 OK\n"
			"Connection: Close\n"
			"Content-Type: video/mpeg\n"
			"Server: stream_enigma2\n\n");
	clientStatus = send(conndata->connfd, http_buf, cs_strlen(http_buf), 0);
	cs_log_dbg(D_CLIENT, "HTTP (send) (%i): %s", clientStatus, remove_newline_chars(http_buf));

	data->connid = conndata->connid;
	data->caid = NO_CAID_VALUE;
	data->blocked_caid = NO_CAID_VALUE;
	data->have_pat_data = 0;
	data->have_pmt_data = 0;
	data->have_cat_data = 0;
	data->have_ecm_data = 0;
	data->have_emm_data = 0;

	while (!exit_oscam && clientStatus != -1 && streamConnectErrorCount < 3
			&& streamDataErrorCount < 15)
	{
		streamfd = connect_to_stream(http_buf, 1024, stream_path, conndata->stream_host, &stream_host_ip[conndata->connid]);
		if (streamfd == -1)
		{
			cs_log("WARNING: stream client %i - cannot connect to stream source host. ip=%s port=%d path=%s", conndata->connid, cs_inet_ntoa(stream_host_ip[conndata->connid]), cfg.stream_source_port, stream_path);
			streamConnectErrorCount++;
			cs_sleepms(500);
			continue;
		}
		streamStatus = 0;
		bytesRead = 0;
		while (!exit_oscam && clientStatus != -1 && streamStatus != -1
#if 0
				&& streamConnectErrorCount < 3 && streamDataErrorCount < 15)
#else
				&& (streamConnectErrorCount < 3 || streamDataErrorCount < 15))
#endif
		{
			if(!streamrelay_client[conndata->connid] || streamrelay_client[conndata->connid]->kill)
			{
				clientStatus = -1;
				break;
			}

			cs_ftime(&start);
			streamStatus = recv(streamfd, stream_buf + bytesRead, cur_dvb_buffer_size - bytesRead, MSG_WAITALL);
			if (streamStatus == 0) // socket closed
			{
				cs_log_dbg(D_CLIENT, "STATUS: streamStatus=%i, streamfd=%i, last_streamfd=%i, streamConnectErrorCount=%i, streamDataErrorCount=%i, bytesRead=%i",
						streamStatus, streamfd, last_streamfd, streamConnectErrorCount, streamDataErrorCount, bytesRead);
				if(streamfd == last_streamfd)
				{
					cs_log("WARNING: stream client %i - stream source closed connection.", conndata->connid);
					if(cfg.stream_client_source_host && conndata->stream_host != cfg.stream_source_host && streamDataErrorCount > 0)
					{
						cs_strncpy(conndata->stream_host, cfg.stream_source_host, sizeof(conndata->stream_host));
						cs_log("FALLBACK: stream client %i - try using stream source host from config. host=%s", conndata->connid, conndata->stream_host);
					}
				}
				cs_log_dbg(D_CLIENT, "HTTP (recv) (%i): %s", streamStatus, remove_newline_chars((const char*)stream_buf));
				streamConnectErrorCount++;
				cs_sleepms(100);
				break;
			}
			if (streamStatus < 0) // error
			{
				cs_log_dbg(D_CLIENT, "HTTP (recv) (%i): %s", streamStatus, remove_newline_chars((const char*)stream_buf));
				if ((errno == EWOULDBLOCK) | (errno == EAGAIN))
				{
					if(cfg.stream_relay_reconnect_count > 0)
					{
						streamReconnectCount++; // 2 sec timeout * cfg.stream_relay_reconnect_count = seconds no data -> close
						cs_log("WARNING: stream client %i no data from stream source. Trying to reconnect (%i/%i)", conndata->connid, streamReconnectCount, cfg.stream_relay_reconnect_count);
						if(streamReconnectCount >= cfg.stream_relay_reconnect_count)
						{
							clientStatus = -1;
							break;
						}
					}
					else
					{
						cs_log("WARNING: stream client %i no data from stream source.", conndata->connid);
					}
					streamDataErrorCount++; // 2 sec timeout * 15 = seconds no data -> close
					cs_sleepms(100);
					continue;
				}
				cs_log("WARNING: stream client %i error receiving data from stream source.", conndata->connid);
				streamConnectErrorCount++;
				cs_sleepms(100);
				break;
			}
			if (streamStatus < cur_dvb_buffer_size - bytesRead) // probably just received header but no stream
			{
				if (!bytesRead && streamStatus > 13 &&
					sscanf((const char*)stream_buf, "HTTP/%3s %d ", http_version , &http_status_code) == 2 &&
					http_status_code != 200)
				{
					cs_log_dbg(D_CLIENT, "HTTP (recv) (%i): %s", streamStatus, remove_newline_chars((const char*)stream_buf));
					cs_log("ERROR: stream client %i got %d response from stream source!", conndata->connid, http_status_code);
					streamConnectErrorCount++;
					cs_sleepms(100);
					break;
				}
				else
				{
					cs_log_dbg(0, "WARNING: stream client %i non-full buffer from stream source.", conndata->connid);
					streamDataErrorCount++;
					cs_sleepms(100);
				}
			}
			else
			{
				streamDataErrorCount = 0;
			}

			streamConnectErrorCount = 0;
			bytesRead += streamStatus;

			if (bytesRead >= cur_dvb_buffer_wait)
			{
				startOffset = 0;

				// only search if not starting on ts packet or unknown packet size
				if (stream_buf[0] != 0x47 || packetSize == 0)
				{
					SearchTsPackets(stream_buf, bytesRead, &packetSize, &startOffset);
				}

				if (packetSize == 0)
				{
					bytesRead = 0;
				}
				else
				{
					packetCount = ((bytesRead - startOffset) / packetSize);

					// We have both PAT and PMT data - We can start descrambling
					if (data->have_pat_data == 1 && data->have_pmt_data == 1)
					{
						if (data->caid == NO_CAID_VALUE && cfg.stream_relay_ctab.ctnum > 0)
						{
							// No allowed CAID found but CAID filter is configured, disconnect client
							cs_log("Stream client %i caid %04X not enabled in stream relay config",
										conndata->connid, data->blocked_caid);
							stream_client_disconnect(conndata);
							return NULL;
						}
						if ((cfg.stream_relay_ctab.ctnum == 0 || chk_ctab_ex(data->caid, &cfg.stream_relay_ctab)) && data->caid != 0xA101 && data->caid != NO_CAID_VALUE)
						{
								DescrambleTsPackets(data, stream_buf + startOffset, packetCount * packetSize, packetSize, tsbbatch);
								if (!descrambling && cfg.stream_relay_buffer_time) {
									cs_sleepms(cfg.stream_relay_buffer_time);
									descrambling = 1;
								}
						}
					}
					else // Search PAT and PMT packets for service information
					{
						ParseTsPackets(data, stream_buf + startOffset, packetCount * packetSize, packetSize);
					}

					clientStatus = send(conndata->connfd, stream_buf + startOffset, packetCount * packetSize, 0);

					remainingDataPos = startOffset + (packetCount * packetSize);
					remainingDataLength = bytesRead - remainingDataPos;

					if (remainingDataPos < remainingDataLength)
					{
						memmove(stream_buf, stream_buf + remainingDataPos, remainingDataLength);
					}
					else
					{
						memcpy(stream_buf, stream_buf + remainingDataPos, remainingDataLength);
					}

					bytesRead = remainingDataLength;
				}
			}
			cs_ftime(&end);
			stream_resptime[conndata->connid] = comp_timeb(&end, &start);
		}

		last_streamfd = streamfd;
		close(streamfd);
	}

	NULLFREE(http_buf);
	NULLFREE(stream_buf);

	dvbcsa_bs_key_free(key_data[conndata->connid].key[ODD]);
	dvbcsa_bs_key_free(key_data[conndata->connid].key[EVEN]);
	NULLFREE(tsbbatch);

	NULLFREE(data);

	stream_client_disconnect(conndata);
	return NULL;
}

static void *stream_server(void)
{
#ifdef IPV6SUPPORT
	struct sockaddr_in6 servaddr, cliaddr;
#else
	struct sockaddr_in servaddr, cliaddr;
#endif
	socklen_t clilen;
	int32_t connfd, reuse = 1, i;
	int8_t connaccepted;
	stream_client_conn_data *conndata;

	struct s_client *client = first_client;
	client->thread = pthread_self();
	SAFE_SETSPECIFIC(getclient, client);
	set_thread_name(__func__);

	cluster_size = dvbcsa_bs_batch_size();
	has_dvbcsa_ecm = (DVBCSA_HEADER_ECM);
#if !DVBCSA_KEY_ECM
#pragma message "WARNING: Streamrelay is compiled without dvbcsa ecm headers! ECM processing via Streamrelay will not work!"
#endif
#if !STATIC_LIBDVBCSA
	has_dvbcsa_ecm = (dlsym(RTLD_DEFAULT, "dvbcsa_bs_key_set_ecm"));
	is_dvbcsa_static = 0;
#if DVBCSA_KEY_ECM
	dvbcsa_get_ecm_table_fn = dlsym(RTLD_DEFAULT, "dvbcsa_get_ecm_table");
#endif
#endif

	cs_log("%s: (%s) %s dvbcsa parallel mode = %d (relay buffer time: %d ms)%s%s",
		(!DVBCSA_HEADER_ECM || !has_dvbcsa_ecm) ? "WARNING" : "INFO",
		(!has_dvbcsa_ecm) ? "wrong" : "ecm",
		(!is_dvbcsa_static) ? "dynamic" : "static",
		cluster_size,
		cfg.stream_relay_buffer_time,
		(!DVBCSA_HEADER_ECM || !has_dvbcsa_ecm) ? "! ECM processing via Streamrelay does not work!" : "",
		(!DVBCSA_HEADER_ECM) ? " Missing dvbcsa ecm headers during build!" : "");

	if (!stream_server_mutex_init)
	{
		SAFE_MUTEX_INIT(&stream_server_mutex, NULL);
		stream_server_mutex_init = 1;
	}

	SAFE_MUTEX_LOCK(&fixed_key_srvid_mutex);
	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		stream_cur_srvid[i] = NO_SRVID_VALUE;
	}
	SAFE_MUTEX_UNLOCK(&fixed_key_srvid_mutex);

	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		gconnfd[i] = -1;
	}
#ifdef IPV6SUPPORT
	glistenfd = socket(AF_INET6, SOCK_STREAM, 0);
	if (glistenfd == -1)
	{
		cs_log("ERROR: cannot create stream server socket! (errno=%d %s)", errno, strerror(errno));
		return NULL;
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_addr = in6addr_any;
	servaddr.sin6_port = htons(cfg.stream_relay_port);
#else
	glistenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (glistenfd == -1)
	{
		cs_log("ERROR: cannot create stream server socket! (errno=%d %s)", errno, strerror(errno));
		return NULL;
	}

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(cfg.stream_relay_port);
#endif
	setsockopt(glistenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	if (bind(glistenfd,(struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
	{
		cs_log("ERROR: cannot bind to stream server socket! (errno=%d %s)", errno, strerror(errno));
		close(glistenfd);
		return NULL;
	}

	if (listen(glistenfd, 3) == -1)
	{
		cs_log("ERROR: cannot listen to stream server socket! (errno=%d %s)", errno, strerror(errno));
		close(glistenfd);
		return NULL;
	}

	cs_log("Stream Relay server initialized. ip=%s port=%d", cs_inet_ntoa(SIN_GET_ADDR(servaddr)), ntohs(SIN_GET_PORT(servaddr)));

	while (!exit_oscam)
	{
		clilen = sizeof(cliaddr);
		connfd = accept(glistenfd,(struct sockaddr *)&cliaddr, &clilen);

		if (connfd == -1)
		{
			cs_log("ERROR: Calling accept() failed! (errno=%d %s)", errno, strerror(errno));
			break;
		}

		connaccepted = 0;

		if (cs_malloc(&conndata, sizeof(stream_client_conn_data)))
		{
			SAFE_MUTEX_LOCK(&stream_server_mutex);
			if (gconncount < STREAM_SERVER_MAX_CONNECTIONS)
			{
				for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
				{
					if (gconnfd[i] == -1)
					{
						cs_strncpy(ecm_src[i], "dvbapi", sizeof(ecm_src[i]));
						gconnfd[i] = connfd;
						gconncount++;
						connaccepted = 1;

						conndata->connfd = connfd;
						conndata->connid = i;
						client_ip[i] = SIN_GET_ADDR(cliaddr);
						client_port[i] = ntohs(SIN_GET_PORT(cliaddr));
						break;
					}
				}
			}
			SAFE_MUTEX_UNLOCK(&stream_server_mutex);
		}

		if (connaccepted)
		{
			int on = 1;
			if (setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
			{
				cs_log("ERROR: stream client %i setsockopt() failed for TCP_NODELAY!", conndata->connid);
			}

			start_thread("stream client", stream_client_handler, (void*)conndata, NULL, 1, 0);
		}
		else
		{
			shutdown(connfd, 2);
			close(connfd);
			cs_log("ERROR: stream server client dropped because of too many connections (%i)!", STREAM_SERVER_MAX_CONNECTIONS);
		}

		cs_sleepms(20);
	}

	close(glistenfd);

	return NULL;
}

void *streamrelay_handler(struct s_client *UNUSED(cl), uint8_t *UNUSED(mbuf), int32_t module_idx)
{
	char authtmp[128];

	if (cfg.stream_relay_enabled)
	{

		if (cfg.stream_source_auth_user && cfg.stream_source_auth_password)
		{
			snprintf(authtmp, sizeof(authtmp), "%s:%s", cfg.stream_source_auth_user, cfg.stream_source_auth_password);
			b64encode(authtmp, cs_strlen(authtmp), &stream_source_auth);
		}
		mod_idx = module_idx;
		start_thread("stream_server", stream_server, NULL, NULL, 1, 1);
	}
	return NULL;
}

void stop_stream_server(void)
{
	int32_t i;

	SAFE_MUTEX_LOCK(&stream_server_mutex);
	for (i = 0; i < STREAM_SERVER_MAX_CONNECTIONS; i++)
	{
		if (gconnfd[i] != -1)
		{
			shutdown(gconnfd[i], 2);
			close(gconnfd[i]);
			gconnfd[i] = -1;
		}
	}

	gconncount = 0;
	SAFE_MUTEX_UNLOCK(&stream_server_mutex);

#ifdef MODULE_RADEGAST
	close_radegast_connection();
#endif

	shutdown(glistenfd, 2);
	close(glistenfd);

	NULLFREE(stream_source_auth);
}

/*
 * protocol structure
 */
void module_streamrelay(struct s_module *ph)
{
	ph->desc = "streamrelay";
	ph->type = MOD_CONN_SERIAL;
	ph->s_handler = streamrelay_handler;
}
#endif // MODULE_STREAMRELAY
