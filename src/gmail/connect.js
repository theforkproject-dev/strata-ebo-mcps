import { GoogleConnect } from "../google/connect.js";

export class GmailConnect extends GoogleConnect {
  constructor(config, options) { super(config, "gmail", options); }
}
