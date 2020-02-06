#pragma once
#include "../Hunt.h"
#include "hunt/reaction/Reaction.h"
#include "hunt/reaction/Log.h"

#include <set>
#include <string>

namespace Hunts{

	/**
	 * HuntT1130 examines the system for added trusted root certificate authorities,
	 * often used by malware to appear genuine.
	 *
	 * @scans Cursory checks the system event logs for added trusted root certificate
	 *        authorities
	 * @scans Normal Scan not supported.
	 * @scans Intensive Scan not supported.
	 */
	class HuntT1130 : public Hunt {
		 std::set<std::wstring> ValidRootCAs;
	public:
		HuntT1130(HuntRegister& record);

		virtual int ScanCursory(const Scope& scope, Reaction reaction);
	};
}