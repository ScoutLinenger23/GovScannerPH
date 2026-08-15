export const MONITORED_URLS = [
  "https://caloocancity.gov.ph", "https://laspinascity.gov.ph", "https://www.makati.gov.ph",
  "https://www.malabon.gov.ph", "https://www.mandaluyong.gov.ph", "https://manila.gov.ph",
  "https://marikina.gov.ph", "https://muntinlupacity.gov.ph", "https://www.navotas.gov.ph",
  "https://paranaquecity.gov.ph", "https://www.pasay.gov.ph", "https://www.pasigcity.gov.ph",
  "https://pateros.gov.ph", "https://quezoncity.gov.ph", "https://sanjuancity.gov.ph",
  "https://www.taguig.gov.ph", "https://www.valenzuela.gov.ph", "https://www.mmda.gov.ph",
  "https://www.bsp.gov.ph", "https://op-proper.gov.ph", "https://www.ovp.gov.ph",
  "https://www.senate.gov.ph", "https://www.congress.gov.ph", "https://sc.judiciary.gov.ph",
  "https://ca.judiciary.gov.ph", "https://sb.judiciary.gov.ph", "https://cta.judiciary.gov.ph",
  "https://www.dar.gov.ph", "https://www.da.gov.ph", "https://www.dbm.gov.ph",
  "https://www.deped.gov.ph", "https://www.doe.gov.ph", "https://www.denr.gov.ph",
  "https://www.dof.gov.ph", "https://dfa.gov.ph", "https://doh.gov.ph",
  "https://dhsud.gov.ph", "https://dict.gov.ph", "https://www.dilg.gov.ph",
  "https://www.doj.gov.ph", "https://www.dole.gov.ph", "https://www.dnd.gov.ph",
  "https://www.dpwh.gov.ph", "https://www.dost.gov.ph", "https://www.dswd.gov.ph",
  "https://www.tourism.gov.ph", "https://www.dti.gov.ph", "https://www.dotr.gov.ph",
  "https://www.dmw.gov.ph", "https://neda.gov.ph", "https://philsa.gov.ph",
  "https://www.bir.gov.ph", "https://customs.gov.ph", "https://lto.gov.ph",
  "https://ltfrb.gov.ph", "https://nbi.gov.ph", "https://pnp.gov.ph",
  "https://bjmp.gov.ph", "https://bfp.gov.ph", "https://coastguard.gov.ph",
  "https://ched.gov.ph", "https://www.tesda.gov.ph", "https://psa.gov.ph",
  "https://bagong.pagasa.dost.gov.ph", "https://www.phivolcs.dost.gov.ph",
  "https://www.namria.gov.ph", "https://www.sec.gov.ph", "https://www.insurance.gov.ph",
  "https://cda.gov.ph", "https://fda.gov.ph", "https://www.philhealth.gov.ph",
  "https://www.sss.gov.ph", "https://www.gsis.gov.ph", "https://www.pagibigfund.gov.ph",
  "https://csc.gov.ph", "https://comelec.gov.ph", "https://www.coa.gov.ph",
  "https://www.foi.gov.ph", "https://e.gov.ph", "https://www.gov.ph",
  "https://www.officialgazette.gov.ph"
]

export function placeholderScanData() {
  return {
    timestamp: 'Initializing scan...',
    results: MONITORED_URLS.map((url) => ({
      url,
      status: 0,
      latency: 0,
      error: 'SCANNING...',
      uptime: 100,
      history: [],
      historyFull: [],
      incidents: [],
      downSince: null,
    })),
  }
}
