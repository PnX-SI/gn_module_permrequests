export interface AccessRequest {
  id_access_request: number;
  id_author: number;
  id_validator: number | null;
  initialization_date: string | null;
  expiration_date: string | null;
  validated: boolean | null;
  description: string | null;
  taxa: number[];
  permissions: number[];
  status: string | null;
  author: AccessRequestRole | null;
  validator: AccessRequestRole | null;
  cruved: Cruved | null;
}

export interface AccessRequestRole {
  nom_complet: string | null;
}

export interface Cruved {
  C: boolean;
  R: boolean;
  U: boolean;
  V: boolean;
  D: boolean;
}
