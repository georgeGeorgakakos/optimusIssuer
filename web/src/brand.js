// White label.
//
// Everything partner-specific lives in this file and in the --brand-* custom
// properties at the top of styles.css. To rebrand the portal for another
// operator, replace the logos in src/assets, change the values below and the
// brand tokens, and rebuild. No page component needs to change.

import imuLogo from "./assets/imu.png";
import imuEmblem from "./assets/imu-emblem.png";
import iccsLogo from "./assets/iccs.png";

export const BRAND = {
  product: "optimusIssuer",
  tagline: "Credential issuance for the OptimusDB swarm",

  // Shown on the left of the brand strip. The IMU wordmark is dark, so it is
  // always placed on the light strip rather than on the navy band.
  primaryLogo: { src: imuLogo, alt: "Information Management Unit" },

  // Shown on the right. The ICCS mark is circular and keeps its own white
  // ground, so it is placed inside a white disc and clipped to a circle.
  partnerLogo: { src: iccsLogo, alt: "ICCS — Institute of Communication and Computer Systems" },

  // Small mark for the footer.
  emblem: { src: imuEmblem, alt: "" },

  footer:
    "Operated by the Information Management Unit at ICCS for the Swarmchestrate " +
    "project, EU Horizon Europe grant 101135012.",

  version: "1.0",
};
