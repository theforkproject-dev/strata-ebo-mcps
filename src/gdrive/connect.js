import { GoogleConnect } from "../google/connect.js";

export class GdriveConnect extends GoogleConnect {
  constructor(config, options) { super(config, "gdrive", options); }
}
