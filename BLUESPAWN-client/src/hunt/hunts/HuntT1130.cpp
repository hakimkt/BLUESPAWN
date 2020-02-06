#include "hunt/hunts/HuntT1130.h"
#include "hunt/RegistryHunt.h"

#include "util/log/Log.h"
#include "util/eventlogs/EventLogs.h"

using namespace Registry;

namespace Hunts{

	HuntT1130::HuntT1130(HuntRegister& record) : Hunt(record, L"T1131 - Install Root Certificate"){
		dwSupportedScans = (DWORD) Aggressiveness::Cursory;
		dwCategoriesAffected = (DWORD) Category::Configurations;
		dwSourcesInvolved = (DWORD) DataSource::Registry;
		dwTacticsUsed = (DWORD) Tactic::Persistence;
	}

	int HuntT1130::ScanCursory(const Scope& scope, Reaction reaction){
		LOG_INFO("Hunting for T1130 - Install Root Certificate at level Cursory");
		reaction.BeginHunt(GET_INFO());

		int detections = QueryEvents(L"CertificateServicesClient-Lifecycle", 1009, reaction);

		reaction.EndHunt();
		return detections;
	}

}