import { Component, Input, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
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
import { AuthService } from '@geonature/components/auth/auth.service';

import {
  PermissionRequest,
  PermissionRequestScope,
  DEFAULT_SCOPE,
} from '../../models/permissionRequest';
import {
  PermissionRequestPayload,
  PermissionRequestService,
} from '../../services/permissionRequest.service';
import { ROUTE_PATHS } from '../../gnModule.module';
import { Taxon } from '@geonature_common/form/taxonomy/taxonomy.component';
import { AcknowledgementComponent } from './acknowledgement/acknowledgement.component';
import { PERMISSION_REQUEST_SECTIONS } from '../permission-request-common/permission-request-sections';

type PermissionRequestFormValue = {
  description: string | null;
  created_on: NgbDateStruct | string | null;
  expiration_date: NgbDateStruct | string | null;
  id_validator: number | null;
  sensitivity_filter: boolean;
  scope: PermissionRequestScope;
  acknowledgeTerms: boolean;
  taxa: any[];
  taxon_search: string | null;
  areas: number[];
};

@Component({
  standalone: true,
  selector: 'permission-request-form',
  templateUrl: 'permission-request-form.component.html',
  styleUrls: ['./permission-request-form.component.scss'],
  imports: [
    GN2CommonModule,
    CommonModule,
    ReactiveFormsModule,
    MatButtonModule,
    MatCardModule,
    MatIconModule,
    AcknowledgementComponent,
  ],
})
export class PermissionRequestFormComponent {
  isSaving = false;
  readonly shouldDisplayAcknowledgement: boolean;
  readonly PermissionRequestScope = PermissionRequestScope;
  readonly sections = PERMISSION_REQUEST_SECTIONS;
  selectedAreasDefaultItems: Array<{ id_area: number; area_name: string; displayName: string }> =
    [];

  constructor(
    private _permissionRequestService: PermissionRequestService,
    private _dateParser: NgbDateParserFormatter,
    private _formBuilder: FormBuilder,
    private _formService: FormService,
    private _moduleService: ModuleService,
    private _configService: ConfigService,
    private _router: Router,
    private _authService: AuthService
  ) {
    const moduleConfig = this._configService.PERMISSION_REQUEST ?? {};
    this.shouldDisplayAcknowledgement = !!moduleConfig.REQUIRE_TERMS_ACKNOWLEDGEMENT;
    this._setupValidators();
    this._setupAcknowledgementControl();
  }

  // //////////////////////////////////////////////////////////////////////////
  // PermissionRequest
  // //////////////////////////////////////////////////////////////////////////

  _permissionRequest: PermissionRequest | null = null;

  @Input()
  set permissionRequest(permissionRequest: PermissionRequest | null) {
    this._permissionRequest = permissionRequest;
    this._fillFormFromPermissionRequest();
  }
  get permissionRequest(): PermissionRequest | null {
    return this._permissionRequest;
  }

  get authorName(): string | null {
    return (
      this.permissionRequest?.author?.nom_complet ??
      this._authService.getCurrentUser()?.nom_complet ??
      null
    );
  }

  // //////////////////////////////////////////////////////////////////////////
  // Form
  // //////////////////////////////////////////////////////////////////////////

  form: FormGroup = this._buildForm();

  private _buildForm(): FormGroup {
    const group = this._formBuilder.group({
      description: [''],
      created_on: [null],
      expiration_date: [null, [Validators.required]],
      id_validator: [null],
      scope: [DEFAULT_SCOPE, [Validators.required]],
      sensitivity_filter: [true],
      acknowledgeTerms: [false],
      taxa: [[], Validators.required],
      taxon_search: [''],
      areas: [[], Validators.required],
    });
    return group;
  }

  private _setupValidators(): void {
    const initControl = this.createdOnControl;
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

    const rawValue = this.form.value as PermissionRequestFormValue & {
      expiration_date: NgbDateStruct;
    };

    let createdOnValue: string | null = null;
    if (rawValue.created_on) {
      if (typeof rawValue.created_on === 'string') {
        createdOnValue = rawValue.created_on;
      } else {
        createdOnValue = this._dateParser.format(
          rawValue.created_on
        ) as unknown as string;
      }
    }

    const payload: PermissionRequestPayload = {
      description: rawValue.description?.trim() || null,
      created_on: createdOnValue,
      expiration_date: this._dateParser.format(rawValue.expiration_date) as unknown as string,
      taxa: this._extractTaxaIdentifiers(rawValue.taxa),
      areas: this._extractAreaIdentifiers(rawValue.areas),
      scope: rawValue.scope,
      sensitivity_filter: !!rawValue.sensitivity_filter,
    };
    if (rawValue.id_validator !== undefined) {
      payload.id_validator = rawValue.id_validator;
    }

    if (this.permissionRequest) {
      this._permissionRequestService
        .updatePermissionRequest(this.permissionRequest, payload)
        .pipe(
          finalize(() => {
            this.isSaving = false;
          })
        )
        .subscribe({
          next: (updatedPermissionRequest: PermissionRequest) => {
            this._router.navigate([
              `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.permissionRequest(updatedPermissionRequest.id_permission_request)}`,
            ]);
          },
          error: (error: any) => {
            // TODO: throw notifications
          },
        });
    } else {
      const createPayload = { ...payload };
      delete createPayload.id_validator;
      this._permissionRequestService
        .createPermissionRequest(createPayload)
        .pipe(
          finalize(() => {
            this.isSaving = false;
          })
        )
        .subscribe({
          next: (createdPermissionRequest: PermissionRequest) => {
            this._router.navigate([
              `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.permissionRequest(createdPermissionRequest.id_permission_request)}`,
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

  get isSameAsPermissionRequest(): boolean {
    if (!this.permissionRequest) {
      return false;
    }

    const {
      description,
      expiration_date,
      id_validator,
      created_on,
      sensitivity_filter,
      scope,
      taxa,
      areas,
    } = this.form.value as PermissionRequestFormValue;
    const selectedTaxa = this._extractTaxaIdentifiers(taxa);
    const permissionRequestTaxa = (this.permissionRequest.taxa || []).map((taxon) => taxon.cd_nom);
    const normalizedSelectedTaxa = [...selectedTaxa].sort((a, b) => a - b);
    const normalizedPermissionRequestTaxa = [...permissionRequestTaxa].sort((a, b) => a - b);
    const selectedAreas = this._extractAreaIdentifiers(areas);
    const permissionRequestAreas = (this.permissionRequest.areas || []).map((area) => area.id_area);
    const normalizedSelectedAreas = [...selectedAreas].sort((a, b) => a - b);
    const normalizedPermissionRequestAreas = [...permissionRequestAreas].sort((a, b) => a - b);

    const normalizedDescription = (description ?? '').trim();
    const permissionRequestDescription = (this.permissionRequest.description ?? '').trim();

    const normalizedCreatedOn = this._normalizeDateValue(created_on);
    const permissionRequestCreatedOn = this._normalizeDateValue(
      this.permissionRequest.created_on
    );

    const normalizedExpiration = this._normalizeDateValue(expiration_date);
    const permissionRequestExpiration = this._normalizeDateValue(
      this.permissionRequest.expiration_date
    );

    const normalizedValidator = id_validator ?? null;
    const permissionRequestValidator = this.permissionRequest.id_validator ?? null;
    const normalizedSensitivity = !!sensitivity_filter;
    const permissionRequestSensitivity = !!this.permissionRequest.sensitivity_filter;
    const normalizedScope = scope ?? DEFAULT_SCOPE;
    const permissionRequestScope = this.permissionRequest.scope ?? DEFAULT_SCOPE;

    return (
      normalizedDescription === permissionRequestDescription &&
      normalizedCreatedOn === permissionRequestCreatedOn &&
      normalizedExpiration === permissionRequestExpiration &&
      normalizedValidator === permissionRequestValidator &&
      normalizedSensitivity === permissionRequestSensitivity &&
      normalizedScope === permissionRequestScope &&
      normalizedSelectedTaxa.length === normalizedPermissionRequestTaxa.length &&
      normalizedSelectedTaxa.every(
        (taxonId, index) => taxonId === normalizedPermissionRequestTaxa[index]
      ) &&
      normalizedSelectedAreas.length === normalizedPermissionRequestAreas.length &&
      normalizedSelectedAreas.every(
        (areaId, index) => areaId === normalizedPermissionRequestAreas[index]
      )
    );
  }

  onReset(): void {
    this._fillFormFromPermissionRequest();
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

  private _fillFormFromPermissionRequest(): void {
    if (!this.permissionRequest) {
      this.form.reset({
        description: '',
        created_on: null,
        expiration_date: null,
        id_validator: null,
        scope: DEFAULT_SCOPE,
        sensitivity_filter: true,
        acknowledgeTerms: this.shouldDisplayAcknowledgement ? false : true,
        taxa: [],
        taxon_search: '',
        areas: [],
      });
      this.selectedAreasDefaultItems = [];
    } else {
      const createdOnStruct = this.permissionRequest.created_on
        ? this._dateParser.parse(this.permissionRequest.created_on)
        : null;
      const expirationStruct = this.permissionRequest.expiration_date
        ? this._dateParser.parse(this.permissionRequest.expiration_date)
        : null;
      this.form.patchValue({
        description: this.permissionRequest.description,
        created_on: createdOnStruct,
        expiration_date: expirationStruct,
        id_validator: this.permissionRequest.id_validator,
        scope: this.permissionRequest.scope ?? DEFAULT_SCOPE,
        sensitivity_filter: !!this.permissionRequest.sensitivity_filter,
        acknowledgeTerms: true,
        taxa: (this.permissionRequest.taxa || []).map((taxon) => ({
          cd_nom: taxon.cd_nom,
          lb_nom: taxon.lb_nom,
          displayName: taxon.lb_nom,
        })),
        taxon_search: '',
        areas: (this.permissionRequest.areas || []).map((area) => area.id_area),
      });
      this.selectedAreasDefaultItems = (this.permissionRequest.areas || []).map((area) => ({
        id_area: area.id_area,
        area_name: area.area_name,
        displayName: area.area_name,
      }));
    }
    this.form.markAsPristine();
    this.form.updateValueAndValidity({ emitEvent: false });
  }

  get expirationDateControl() {
    return this.form.get('expiration_date');
  }

  get createdOnControl() {
    return this.form.get('created_on');
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

  get areasControl() {
    return this.form.get('areas');
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

  private _extractAreaIdentifiers(value: any): number[] {
    if (!Array.isArray(value)) {
      return [];
    }
    return value
      .map((item) => {
        if (item === null || item === undefined) {
          return null;
        }
        if (typeof item === 'number') {
          return item;
        }
        if (typeof item === 'string' && item.trim() !== '') {
          const parsed = Number(item);
          return Number.isNaN(parsed) ? null : parsed;
        }
        if (typeof item === 'object' && 'id_area' in item) {
          return Number(item['id_area']);
        }
        return null;
      })
      .filter((areaId): areaId is number => areaId !== null);
  }

  onTaxonSelected(event: NgbTypeaheadSelectItemEvent<Taxon>): void {
    const item = event.item;
    if (!item || item.cd_nom === undefined || item.cd_nom === null) {
      return;
    }
    const cd_ref = Number(item.cd_ref);
    if (!Number.isFinite(cd_ref)) {
      this._resetTaxonSearchControl();
      return;
    }
    const currentTaxa = (this.taxaControl?.value as any[]) ?? [];
    const alreadySelected = currentTaxa.some((taxon) => taxon.cd_nom === cd_ref);
    if (alreadySelected) {
      this._resetTaxonSearchControl();
      return;
    }
    const label =
      item.lb_nom || item.nom_valide || item.search_name || item.nom_complet || `${item.cd_nom}`;
    const updatedTaxa = [
      ...currentTaxa,
      {
        cd_nom: cd_ref,
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

  onAreasSelectionChange(selection: any[]): void {
    this.selectedAreasDefaultItems = Array.isArray(selection) ? selection : [];
    this.areasControl?.markAsDirty();
    this.areasControl?.markAsTouched();
  }

  private _resetTaxonSearchControl(): void {
    this.taxonSearchControl?.setValue('', { emitEvent: false });
    this.taxonSearchControl?.markAsPristine();
    this.taxonSearchControl?.markAsUntouched();
  }
}
