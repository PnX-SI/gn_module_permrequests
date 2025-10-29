import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { Router } from '@angular/router';

import {
  NgbDateParserFormatter,
  NgbDateStruct,
  NgbTypeaheadSelectItemEvent,
} from '@ng-bootstrap/ng-bootstrap';

import { finalize } from 'rxjs/operators';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { FormService } from '@geonature_common/form/form.service';
import { ModuleService } from '@geonature/services/module.service';
import { ConfigService } from '@geonature/services/config.service';

import { AccessRequest, AccessRequestScope, DEFAULT_SCOPE } from '../../models/accessRequest';
import { AccessRequestPayload, AccessRequestService } from '../../services/accessRequest.service';
import { ROUTE_PATHS } from '../../gnModule.module';
import { Taxon } from '@geonature_common/form/taxonomy/taxonomy.component';


type AccessRequestFormValue = {
  description: string | null;
  initialization_date: NgbDateStruct | string | null;
  expiration_date: NgbDateStruct | string | null;
  id_validator: number | null;
  sensitivity_filter: boolean;
  scope: AccessRequestScope;
  acknowledgeTerms: boolean;
  taxa: any[];
  taxon_search: string | null;
};

@Component({
  standalone: true,
  selector: 'access-request-form',
  templateUrl: 'access-request-form.component.html',
  styleUrls: ['./access-request-form.component.scss'],
  imports: [GN2CommonModule, CommonModule, ReactiveFormsModule, MatButtonModule],
})
export class AccessRequestFormComponent {
  isSaving = false;
  readonly shouldDisplayAcknowledgement: boolean;
  readonly termsAcknowledgementText: string;
  readonly AccessRequestScope = AccessRequestScope;

  constructor(
    private _accessRequestService: AccessRequestService,
    private _dateParser: NgbDateParserFormatter,
    private _formBuilder: FormBuilder,
    private _formService: FormService,
    private _moduleService: ModuleService,
    private _configService: ConfigService,
    private _router: Router
  ) {
    const moduleConfig = this._configService.ACCESS_REQUEST ?? {};
    this.shouldDisplayAcknowledgement = !!moduleConfig.REQUIRE_TERMS_ACKNOWLEDGEMENT;
    this.termsAcknowledgementText = moduleConfig.TERMS_ACKNOWLEDGMENT.TEXT.trim();
    this._setupValidators();
    this._setupAcknowledgementControl();
  }

  // //////////////////////////////////////////////////////////////////////////
  // AccessRequest
  // //////////////////////////////////////////////////////////////////////////

  _accessRequest: AccessRequest | null = null;

  @Input()
  set accessRequest(accessRequest: AccessRequest | null) {
    this._accessRequest = accessRequest;
    this._fillFormFromAccessRequest(accessRequest);
  }
  get accessRequest(): AccessRequest | null {
    return this._accessRequest;
  }

  // //////////////////////////////////////////////////////////////////////////
  // Form
  // //////////////////////////////////////////////////////////////////////////

  form: FormGroup = this._buildForm();

  private _buildForm(): FormGroup {
    const group = this._formBuilder.group({
      description: [''],
      initialization_date: [null],
      expiration_date: [null, [Validators.required]],
      id_validator: [null],
      scope: [DEFAULT_SCOPE, [Validators.required]],
      sensitivity_filter: [true],
      acknowledgeTerms: [false, Validators.requiredTrue],
      taxa: [[], Validators.required],
      taxon_search: [''],
    });
    return group;
  }

  private _setupValidators(): void {
    const initControl = this.initializationDateControl;
    const expirationControl = this.expirationDateControl;
    if (initControl && expirationControl) {
      const baseValidator = this._formService.dateValidator(initControl, expirationControl);
      this.form.setValidators(baseValidator);
      this.form.updateValueAndValidity({ emitEvent: false });
    }
  }

  private _setupAcknowledgementControl(): void {
    const control = this.acknowledgeTermsControl;
    if (!control) {
      return;
    }
    if (this.shouldDisplayAcknowledgement) {
      control.setValidators(Validators.requiredTrue);
      control.setValue(false, { emitEvent: false });
    } else {
      control.clearValidators();
      control.setValue(true, { emitEvent: false });
    }
    control.updateValueAndValidity({ emitEvent: false });
  }

  onSubmit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    this.isSaving = true;

    const rawValue = this.form.value as AccessRequestFormValue & {
      expiration_date: NgbDateStruct;
    };

    let initializationValue: string | null = null;
    if (rawValue.initialization_date) {
      if (typeof rawValue.initialization_date === 'string') {
        initializationValue = rawValue.initialization_date;
      } else {
        initializationValue = this._dateParser.format(
          rawValue.initialization_date
        ) as unknown as string;
      }
    }

    const payload: AccessRequestPayload = {
      description: rawValue.description?.trim() || null,
      initialization_date: initializationValue,
      expiration_date: this._dateParser.format(rawValue.expiration_date) as unknown as string,
      taxa: this._extractTaxaIdentifiers(rawValue.taxa),
      scope: rawValue.scope,
      sensitivity_filter: !!rawValue.sensitivity_filter,
    };
    if (rawValue.id_validator !== undefined) {
      payload.id_validator = rawValue.id_validator;
    }

    if (this.accessRequest) {
      this._accessRequestService
        .updateAccessRequest(this.accessRequest, payload)
        .pipe(
          finalize(() => {
            this.isSaving = false;
          })
        )
        .subscribe({
          next: (updatedAccessRequest: AccessRequest) => {
            this._router.navigate([
              `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.accessRequest(updatedAccessRequest.id_access_request)}`,
            ]);
          },
          error: (error: any) => {
            // TODO: throw notifications
          },
        });
    } else {
      const createPayload = { ...payload };
      delete createPayload.id_validator;
      this._accessRequestService
        .createAccessRequest(createPayload)
        .pipe(
          finalize(() => {
            this.isSaving = false;
          })
        )
        .subscribe({
          next: (createdAccessRequest: AccessRequest) => {
            this._router.navigate([
              `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.accessRequest(createdAccessRequest.id_access_request)}`,
            ]);
          },
          error: (error: any) => {
            // TODO: throw notifications
          },
        });
    }
  }

  // //////////////////////////////////////////////////////////////////////////
  // Form Helpers
  // //////////////////////////////////////////////////////////////////////////

  get isSameAsAccessRequest(): boolean {
    if (!this.accessRequest) {
      return false;
    }

    const {
      description,
      expiration_date,
      id_validator,
      initialization_date,
      sensitivity_filter,
      scope,
      taxa,
    } = this.form
      .value as AccessRequestFormValue;
    const selectedTaxa = this._extractTaxaIdentifiers(taxa);
    const accessRequestTaxa = (this.accessRequest.taxa || []).map((taxon) => taxon.cd_nom);
    const normalizedSelectedTaxa = [...selectedTaxa].sort((a, b) => a - b);
    const normalizedAccessRequestTaxa = [...accessRequestTaxa].sort((a, b) => a - b);

    const normalizedDescription = (description ?? '').trim();
    const accessRequestDescription = (this.accessRequest.description ?? '').trim();

    const normalizedInitialization = this._normalizeDateValue(initialization_date);
    const accessRequestInitialization = this._normalizeDateValue(
      this.accessRequest.initialization_date
    );

    const normalizedExpiration = this._normalizeDateValue(expiration_date);
    const accessRequestExpiration = this._normalizeDateValue(this.accessRequest.expiration_date);

    const normalizedValidator = id_validator ?? null;
    const accessRequestValidator = this.accessRequest.id_validator ?? null;
    const normalizedSensitivity = !!sensitivity_filter;
    const accessRequestSensitivity = !!this.accessRequest.sensitivity_filter;
    const normalizedScope = scope ?? DEFAULT_SCOPE;
    const accessRequestScope = this.accessRequest.scope ?? DEFAULT_SCOPE;

    return (
      normalizedDescription === accessRequestDescription &&
      normalizedInitialization === accessRequestInitialization &&
      normalizedExpiration === accessRequestExpiration &&
      normalizedValidator === accessRequestValidator &&
      normalizedSensitivity === accessRequestSensitivity &&
      normalizedScope === accessRequestScope &&
      normalizedSelectedTaxa.length === normalizedAccessRequestTaxa.length &&
      normalizedSelectedTaxa.every((taxonId, index) => taxonId === normalizedAccessRequestTaxa[index])
    );
  }

  onReset(): void {
    this._fillFormFromAccessRequest(this.accessRequest);
  }

  private _normalizeDateValue(value: NgbDateStruct | string | null | undefined): string | null {
    if (!value) {
      return null;
    }
    if (typeof value === 'string') {
      return value || null;
    }
    return this._dateParser.format(value) as unknown as string;
  }

  private _fillFormFromAccessRequest(accessRequest: AccessRequest | null): void {
    if (!accessRequest) {
      this.form.reset({
        description: '',
        initialization_date: null,
        expiration_date: null,
        id_validator: null,
        scope: DEFAULT_SCOPE,
        sensitivity_filter: true,
        acknowledgeTerms: this.shouldDisplayAcknowledgement ? false : true,
        taxa: [],
        taxon_search: '',
      });
    } else {
      const initializationStruct = accessRequest.initialization_date
        ? this._dateParser.parse(accessRequest.initialization_date)
        : null;
      const expirationStruct = accessRequest.expiration_date
        ? this._dateParser.parse(accessRequest.expiration_date)
        : null;
      this.form.patchValue({
        description: accessRequest.description,
        initialization_date: initializationStruct,
        expiration_date: expirationStruct,
        id_validator: accessRequest.id_validator,
        scope: accessRequest.scope ?? DEFAULT_SCOPE,
        sensitivity_filter: !!accessRequest.sensitivity_filter,
        acknowledgeTerms: true,
        taxa: (accessRequest.taxa || []).map((taxon) => ({
          cd_nom: taxon.cd_nom,
          lb_nom: taxon.lb_nom,
          displayName: taxon.lb_nom,
        })),
        taxon_search: '',
      });
    }
    this.form.markAsPristine();
    this.form.updateValueAndValidity({ emitEvent: false });
  }

  get expirationDateControl() {
    return this.form.get('expiration_date');
  }

  get initializationDateControl() {
    return this.form.get('initialization_date');
  }

  get acknowledgeTermsControl() {
    return this.form.get('acknowledgeTerms');
  }

  get scopeControl() {
    return this.form.get('scope');
  }

  get sensitivityFilterControl() {
    return this.form.get('sensitivity_filter');
  }

  get taxaControl() {
    return this.form.get('taxa');
  }

  get taxonSearchControl() {
    return this.form.get('taxon_search');
  }

  private _extractTaxaIdentifiers(value: any): number[] {
    if (!Array.isArray(value)) {
      return [];
    }
    return value
      .map((item) => {
        if (!item) {
          return null;
        }
        if (typeof item === 'number') {
          return item;
        }
        if (typeof item === 'string' && item.trim() !== '') {
          const parsed = Number(item);
          return Number.isNaN(parsed) ? null : parsed;
        }
        if (typeof item === 'object' && 'cd_nom' in item) {
          return Number(item['cd_nom']);
        }
        return null;
      })
      .filter((taxonId): taxonId is number => taxonId !== null);
  }

  onTaxonSelected(event: NgbTypeaheadSelectItemEvent<Taxon>): void {
    const item = event.item;
    if (!item || item.cd_nom === undefined || item.cd_nom === null) {
      return;
    }
    const cdNom = Number(item.cd_nom);
    if (!Number.isFinite(cdNom)) {
      this._resetTaxonSearchControl();
      return;
    }
    const currentTaxa = (this.taxaControl?.value as any[]) ?? [];
    const alreadySelected = currentTaxa.some((taxon) => taxon.cd_nom === cdNom);
    if (alreadySelected) {
      this._resetTaxonSearchControl();
      return;
    }
    const label =
      item.lb_nom || item.nom_valide || item.search_name || item.nom_complet || `${item.cd_nom}`;
    const updatedTaxa = [
      ...currentTaxa,
      {
        cd_nom: cdNom,
        lb_nom: label,
        displayName: label,
      },
    ];
    this.taxaControl?.setValue(updatedTaxa);
    this.taxaControl?.markAsDirty();
    this.taxaControl?.markAsTouched();
    this.taxaControl?.updateValueAndValidity({ emitEvent: false });
    this._resetTaxonSearchControl();
  }

  removeTaxon(cd_nom: number): void {
    const currentTaxa = (this.taxaControl?.value as any[]) ?? [];
    const updatedTaxa = currentTaxa.filter((taxon) => taxon.cd_nom !== cd_nom);
    this.taxaControl?.setValue(updatedTaxa);
    this.taxaControl?.markAsDirty();
    this.taxaControl?.markAsTouched();
    this.taxaControl?.updateValueAndValidity({ emitEvent: false });
  }

  private _resetTaxonSearchControl(): void {
    this.taxonSearchControl?.setValue('', { emitEvent: false });
    this.taxonSearchControl?.markAsPristine();
    this.taxonSearchControl?.markAsUntouched();
  }
}
