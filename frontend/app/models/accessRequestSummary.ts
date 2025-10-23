export interface AccessRequestSummary {
  id_access_request: number;
  id_validation_status: number | null;
  id_author: number;
  id_validator: number | null;
  expiration_date: string | null;
  description: string | null;
  taxa: number[];
  permissions: number[];
}
