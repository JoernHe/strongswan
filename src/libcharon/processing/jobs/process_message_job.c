/*
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "process_message_job.h"

#include <daemon.h>

typedef struct private_process_message_job_t private_process_message_job_t;

/**
 * Private data of an process_message_job_t Object
 */
struct private_process_message_job_t {
	/**
	 * public process_message_job_t interface
	 */
	process_message_job_t public;

	/**
	 * Message associated with this job
	 */
	message_t *message;
};

/**
 * get the child_cfg with the same name as the peer cfg
 */
static child_cfg_t* get_child_from_peer(peer_cfg_t *peer_cfg, char *name)
{
	child_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;

	enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(job_t, destroy, void,
	private_process_message_job_t *this)
{
	this->message->destroy(this->message);
	free(this);
}

bool initiate_cb(void* param, debug_t group, level_t level, ike_sa_t* ike_sa, const char *message)
{
	ike_sa_t *mitm_ike_sa = (ike_sa_t *)param;
	if (ike_sa && mitm_ike_sa)
	{
		ike_sa->set_mitm(ike_sa, mitm_ike_sa);
		mitm_ike_sa->set_mitm(mitm_ike_sa, ike_sa);
		return TRUE;
	}

	return FALSE;
}

METHOD(job_t, execute, job_requeue_t,
	private_process_message_job_t *this)
{
	ike_sa_t *ike_sa;

#ifdef ME
	/* if this is an unencrypted INFORMATIONAL exchange it is likely a
	 * connectivity check. */
	if (this->message->get_exchange_type(this->message) == INFORMATIONAL &&
		this->message->get_first_payload_type(this->message) != PLV2_ENCRYPTED)
	{
		/* theoretically this could also be an error message
		 * see RFC 4306, section 1.5. */
		DBG1(DBG_NET, "received unencrypted informational: from %#H to %#H",
			 this->message->get_source(this->message),
			 this->message->get_destination(this->message));
		charon->connect_manager->process_check(charon->connect_manager, this->message);
		return JOB_REQUEUE_NONE;
	}
#endif /* ME */

	ike_sa = charon->ike_sa_manager->checkout_by_message(charon->ike_sa_manager,
														 this->message);
	if (ike_sa)
	{
		DBG1(DBG_NET, "received packet: from %#H to %#H (%zu bytes)",
			 this->message->get_source(this->message),
			 this->message->get_destination(this->message),
			 this->message->get_packet_data(this->message).len);
		status_t ret = ike_sa->process_message(ike_sa, this->message);
		if (ret == DESTROY_ME)
		{
			charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
		}
		else if (ret == SUCCESS && this->message->get_exchange_type(this->message) == IKE_SA_INIT)
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			ike_cfg_t *ike_cfg = ike_sa->get_ike_cfg(ike_sa);
			if (ike_cfg)
			{
				char *mitm = ike_cfg->get_mitm(ike_cfg);
				if (mitm)
				{
					peer_cfg_t *mitm_peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends, mitm);
					if (mitm_peer_cfg)
					{
						child_cfg_t *mitm_child_cfg = get_child_from_peer(mitm_peer_cfg, mitm_peer_cfg->get_name(mitm_peer_cfg));
						if (mitm_child_cfg)
						{
							DBG1(DBG_IKE, "MITM starting connection '%s'", mitm);
							charon->controller->initiate(charon->controller, mitm_peer_cfg, mitm_child_cfg, &initiate_cb, ike_sa, 0, FALSE);
						}
					}
				}
			}
		}
		else
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		}
	}
	return JOB_REQUEUE_NONE;
}

METHOD(job_t, get_priority, job_priority_t,
	private_process_message_job_t *this)
{
	switch (this->message->get_exchange_type(this->message))
	{
		case IKE_AUTH:
			/* IKE auth is rather expensive and often blocking, low priority */
		case AGGRESSIVE:
		case ID_PROT:
			/* AM is basically IKE_SA_INIT/IKE_AUTH combined (without EAP/XAuth)
			 * MM is similar, but stretched out more */
			return JOB_PRIO_LOW;
		case INFORMATIONAL:
		case INFORMATIONAL_V1:
			/* INFORMATIONALs are inexpensive, for DPD we should have low
			 * reaction times */
			return JOB_PRIO_HIGH;
		case IKE_SA_INIT:
			/* IKE_SA_INIT is expensive, but we will drop them in the receiver
			 * if we are overloaded */
		case CREATE_CHILD_SA:
		case QUICK_MODE:
			/* these may require DH, but if not they are relatively cheap */
		case TRANSACTION:
			/* these are mostly cheap, however, if XAuth via RADIUS is used
			 * they may block */
		default:
			return JOB_PRIO_MEDIUM;
	}
}

/*
 * Described in header
 */
process_message_job_t *process_message_job_create(message_t *message)
{
	private_process_message_job_t *this;

	INIT(this,
		.public = {
			.job_interface = {
				.execute = _execute,
				.get_priority = _get_priority,
				.destroy = _destroy,
			},
		},
		.message = message,
	);

	if (message->get_request(message) &&
		message->get_exchange_type(message) == IKE_SA_INIT)
	{
		charon->ike_sa_manager->track_init(charon->ike_sa_manager,
										   message->get_source(message));
	}
	if (message->get_exchange_type(message) == ID_PROT ||
		message->get_exchange_type(message) == AGGRESSIVE)
	{
		ike_sa_id_t *id = message->get_ike_sa_id(message);

		if (id->get_responder_spi(id) == 0)
		{
			charon->ike_sa_manager->track_init(charon->ike_sa_manager,
											   message->get_source(message));
		}
	}
	return &(this->public);
}
