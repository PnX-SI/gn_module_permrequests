import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  FormBuilder,
  FormGroup,
  ReactiveFormsModule,
  UntypedFormControl,
  ValidationErrors,
  ValidatorFn,
  Validators,
} from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { Router } from '@angular/router';

import {
  NgbDateParserFormatter,
  NgbDateStruct,
  NgbTypeaheadSelectItemEvent,
} from '@ng-bootstrap/ng-bootstrap';
import { finalize } from '@librairies/rxjs/operators';
import { TranslateService } from '@ngx-translate/core';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { CommonService } from '@geonature_common/service/common.service';
import { DateStruc } from '@geonature_common/form/date/date.component';
import { Taxon } from '@geonature_common/form/taxonomy/taxonomy.component';
import { ModuleService } from '@geonature/services/module.service';
import { ConfigService } from '@geonature/services/config.service';
import { AuthService } from '@geonature/components/auth/auth.service';
import { I18nService } from '@geonature/shared/translate/i18n-service';

import {
  DEFAULT_SCOPE,
  PermissionRequest,
  PermissionRequestScope,
} from '../../models/permissionRequest';
import {
  PermissionRequestPayload,
  PermissionRequestService,
} from '../../services/permissionRequest.service';
import { ROUTE_PATHS } from '../../gnModule.module';
import { AcknowledgementComponent } from './acknowledgement/acknowledgement.component';
import { PERMISSION_REQUEST_SECTIONS } from '../permission-request-common/permission-request-sections';
import {
  AccessRequestData,
  ConventiondDialogContent,
} from './convention-dialog/convention-dialog.component';
import { TaxaComponent } from '../shared/taxa/taxa.component';

export type AreaMode = 'existing' | 'custom';

type PermissionRequestFormValue = {
  description: string | null;
  expiration_date: NgbDateStruct | string | null;
  sensitivity_filter: boolean;
  scope: PermissionRequestScope;
  acknowledgeTerms: boolean;
  taxa: any[];
  areas: number[];
  area_mode: AreaMode;
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
    MatDialogModule,
    MatIconModule,
    AcknowledgementComponent,
    TaxaComponent,
  ],
})
export class PermissionRequestFormComponent {
  isSaving = false;
  readonly shouldDisplayAcknowledgement: boolean;

  readonly shouldDisplaySensitivityFilter: boolean;
  readonly sensitivityFilterDefaultValue: boolean;

  readonly shouldDisplayScopeFilter: boolean;
  readonly scopeFilterDefaultValue: PermissionRequestScope;

  readonly allowCustomArea: boolean;
  readonly PermissionRequestScope = PermissionRequestScope;
  readonly sections = PERMISSION_REQUEST_SECTIONS;

  readonly shouldDisplayConvention: boolean;
  conventionRequestData: AccessRequestData = {
    areas: [],
    taxa: [],
    sensitivity_filter: null,
    expiration_date: null,
  };

  selectedTaxaDefaultItems: Array<any> = [];

  selectedAreasDefaultItems: Array<{ id_area: number; area_name: string; displayName: string }> =
    [];

  parsedGeoJson: object | null = null;
  geoJsonParseError: string | null = null;
  selectedGeoJsonFileName: string | null = null;

  readonly today: Date = new Date();
  readonly dayDuration = 864e5;
  readonly defaultPermissionsDays: number;
  readonly maxPermissionsDays: number;
  readonly defaultEndExpirationDate: DateStruc;
  readonly minExpirationDate: DateStruc;
  readonly maxExpirationDate: DateStruc;

  readonly shouldDisplayDynamicForm: boolean;
  dynamicFormGrp: FormGroup;
  readonly dynamicFormCfg: any[];

  constructor(
    private _permissionRequestService: PermissionRequestService,
    private _dateParser: NgbDateParserFormatter,
    private _formBuilder: FormBuilder,
    private _moduleService: ModuleService,
    private _configService: ConfigService,
    private _router: Router,
    private _authService: AuthService,
    private _translateService: TranslateService,
    private _i18nService: I18nService,
    private _dialog: MatDialog,
    private _commonService: CommonService
  ) {
    const moduleConfig = this._configService.PERMREQUESTS ?? {};

    this.allowCustomArea = !!moduleConfig.ALLOW_CUSTOM_AREA;

    this.defaultPermissionsDays = moduleConfig.PERMISSIONS_DURATION.DEFAULT_DAYS;
    this.maxPermissionsDays = moduleConfig.PERMISSIONS_DURATION.MAX_DAYS;

    this.shouldDisplayScopeFilter = !!moduleConfig.SCOPE_FILTER.DISPLAY_ENABLED;
    this.scopeFilterDefaultValue = moduleConfig.SCOPE_FILTER.DEFAULT_VALUE ?? DEFAULT_SCOPE;

    this.shouldDisplaySensitivityFilter = !!moduleConfig.SENSITIVITY_FILTER.DISPLAY_ENABLED;
    this.sensitivityFilterDefaultValue = !!moduleConfig.SENSITIVITY_FILTER.DEFAULT_VALUE;

    this.shouldDisplayAcknowledgement = !!moduleConfig.TERMS_ACKNOWLEDGEMENT.REQUIRED;

    this.defaultEndExpirationDate = this.getDefaultEndExpirationDate();
    this.minExpirationDate = this.getMinExpirationDate();
    this.maxExpirationDate = this.getMaxExpirationDate();

    this.shouldDisplayDynamicForm = moduleConfig.DYNAMIC_FORM.length > 0 ? true : false;
    this.dynamicFormCfg = moduleConfig.DYNAMIC_FORM ?? [];

    this.shouldDisplayConvention = !!moduleConfig.ENABLE_CONVENTION;

    this.form = this._buildForm();
    this._setupAreasValidator();
    this._setupAcknowledgementControl();

    this.dynamicFormGrp = this.createDynamicForm();

    this._i18nService.initializeModuleTranslateService(this._translateService);
  }

  // //////////////////////////////////////////////////////////////////////////
  // PermissionRequest
  // //////////////////////////////////////////////////////////////////////////

  _permissionRequest: PermissionRequest | null = null;

  @Input()
  set permissionRequest(permissionRequest: PermissionRequest | null) {
    this._permissionRequest = permissionRequest;
    this._fillFormFromPermissionRequest();
    this._fillDynamicFormFromPermissionRequest();
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

  form: FormGroup;

  private _buildForm(): FormGroup {
    let defaultFormGroup = {
      description: [''],
      expiration_date: [this.defaultEndExpirationDate, [Validators.required]],
      scope: [this.scopeFilterDefaultValue, [Validators.required]],
      sensitivity_filter: [this.sensitivityFilterDefaultValue],
      acknowledgeTerms: [false, this.shouldDisplayAcknowledgement ? Validators.requiredTrue : []],
      taxa: [[]],
      areas: [[], Validators.required],
      area_mode: ['existing' as AreaMode],
    };
    return this._formBuilder.group(defaultFormGroup);
  }

  private areasValidator(): ValidatorFn {
    return (): ValidationErrors | null => {
      if (this.isAreaValid) {
        return null;
      }
      return { invalidAreas: true };
    };
  }

  private _setupAreasValidator(): void {
    // Areas Validator - depends on areas mode
    this._updateAreasValidators();

    // Listener on area_mode change to update areas validators
    const areaModeControl = this.form.get('area_mode');
    if (areaModeControl) {
      areaModeControl.valueChanges.subscribe(() => {
        this._updateAreasValidators();
      });
    }
  }

  private _updateAreasValidators(): void {
    const areasControl = this.areasControl;
    if (!areasControl) return;

    // areas est requis uniquement en mode "existing"
    const validators = this.isCustomAreaMode
      ? [this.areasValidator()]
      : [Validators.required, this.areasValidator()];
    areasControl.setValidators(validators);
    areasControl.updateValueAndValidity({ emitEvent: false });
  }

  private _setupAcknowledgementControl(): void {
    const control = this.acknowledgeTermsControl;
    if (!control) return;
    if (this.shouldDisplayAcknowledgement) {
      control.setValidators(Validators.requiredTrue);
      control.setValue(false, { emitEvent: false });
    } else {
      control.clearValidators();
      control.setValue(true, { emitEvent: false });
    }
    control.updateValueAndValidity({ emitEvent: false });
  }

  // //////////////////////////////////////////////////////////////////////////
  // Permission expiration date
  // //////////////////////////////////////////////////////////////////////////

  private getMinExpirationDate(): DateStruc {
    return this.transformToDateObject(this.today);
  }

  private getMaxExpirationDate(): DateStruc {
    const maxPermissionsDuration = this.dayDuration * this.maxPermissionsDays;
    const in2YearsDate = new Date(this.today.valueOf() + maxPermissionsDuration);
    return this.transformToDateObject(in2YearsDate);
  }

  private getDefaultEndExpirationDate(): DateStruc {
    const defaultPermissionsDuration = this.dayDuration * this.defaultPermissionsDays;
    const defaultEndExpirationDate = new Date(this.today.valueOf() + defaultPermissionsDuration);
    return this.transformToDateObject(defaultEndExpirationDate);
  }

  private transformToDateObject(date: Date): DateStruc {
    return {
      year: date.getFullYear(),
      month: date.getMonth() + 1,
      day: date.getDate(),
    };
  }

  // //////////////////////////////////////////////////////////////////////////
  // Area mode
  // //////////////////////////////////////////////////////////////////////////

  get areaMode(): AreaMode {
    return this.form.get('area_mode')?.value ?? 'existing';
  }

  get isCustomAreaMode(): boolean {
    return this.areaMode === 'custom';
  }

  onAreaModeChange(mode: AreaMode): void {
    this.form.get('area_mode')?.setValue(mode);
    this.form.markAsDirty();
  }

  onGeoJsonFileChange(event: Event): void {
    this.geoJsonParseError = null;
    this.parsedGeoJson = null;
    this.selectedGeoJsonFileName = null;

    const file = (event.target as HTMLInputElement).files?.[0] ?? null;
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        try {
          this.parsedGeoJson = JSON.parse(reader.result as string);
          this.selectedGeoJsonFileName = file.name;
          this.areasControl?.updateValueAndValidity({ emitEvent: false });
          this.form.markAsDirty();
        } catch {
          this.geoJsonParseError = "Le GeoJSON fourni n'est pas valide.";
          this.areasControl?.updateValueAndValidity({ emitEvent: false });
        }
      };
      reader.onerror = () => {
        this.geoJsonParseError = "Le GeoJSON fourni n'est pas valide.";
        this.areasControl?.updateValueAndValidity({ emitEvent: false });
      };
      reader.readAsText(file);
    }
  }

  get isCustomAreaValid(): boolean {
    let isCustomAreaValid = false;
    if (
      !this.isCustomAreaMode ||
      (this.permissionRequest?.custom_area && !this.parsedGeoJson) ||
      (this.parsedGeoJson !== null && this.geoJsonParseError === null)
    ) {
      isCustomAreaValid = true;
    }
    return isCustomAreaValid;
  }

  get isAreaValid(): boolean {
    let isAreaValid = this.isCustomAreaMode
      ? this.isCustomAreaValid
      : this._extractAreaIdentifiers(this.areasControl?.value).length > 0;
    return isAreaValid;
  }

  // //////////////////////////////////////////////////////////////////////////
  // Dynamic form group (custom fields)
  // //////////////////////////////////////////////////////////////////////////

  private createDynamicForm() {
    return this._formBuilder.group({});
  }

  // //////////////////////////////////////////////////////////////////////////
  // Submit
  // //////////////////////////////////////////////////////////////////////////

  onSubmit(): void {
    if (this.form.invalid || this.dynamicFormGrp.invalid || !this.isAreaValid) {
      if (this.form.invalid) {
        this.form.markAllAsTouched();
      }
      if (this.dynamicFormGrp.invalid) {
        this.dynamicFormGrp.markAllAsTouched();
      }
      return;
    }

    this.isSaving = true;

    const payload: PermissionRequestPayload = this.buildPayload();
    if (this.shouldDisplayConvention) {
      this.showConvention(payload);
    } else {
      this.sendAccessRequest(payload);
    }
  }

  private buildPayload(): PermissionRequestPayload {
    const rawValue = this.getRegularFormValues();
    const payload: PermissionRequestPayload = {
      description: rawValue.description?.trim() || null,
      expiration_date: this._dateParser.format(rawValue.expiration_date) as unknown as string,
      taxa: this._extractTaxaIdentifiers(rawValue.taxa),
      areas: this.isCustomAreaMode ? [] : this._extractAreaIdentifiers(rawValue.areas),
      scope: rawValue.scope,
      sensitivity_filter: !!rawValue.sensitivity_filter,
      custom_area: this._buildCustomAreaPayload(),
    };

    if (this.shouldDisplayDynamicForm) {
      payload['additional_data'] = this.getDynamicFormValues();
    }

    return payload;
  }

  private getRegularFormValues() {
    const rawValue = this.form.value as PermissionRequestFormValue & {
      expiration_date: NgbDateStruct;
    };
    return rawValue;
  }

  private getDynamicFormValues() {
    return this.dynamicFormGrp.value;
  }

  private showConvention(payload: PermissionRequestPayload) {
    const dialogRef = this.openConventionDialog();
    dialogRef.afterClosed().subscribe((conventionAccepted) => {
      if (conventionAccepted === true) {
        this.sendAccessRequest(payload);
      } else {
        this.isSaving = false;
        this._commonService.translateToaster('warning', 'Permrequests.Convention.Canceled');
      }
    });
  }

  private buildConventionAccessRequestData(): AccessRequestData {
    const formValues = this.getRegularFormValues();
    this.conventionRequestData = {
      areas: this.conventionRequestData.areas,
      taxa: this.conventionRequestData.taxa,
      sensitivity_filter: formValues.sensitivity_filter,
      expiration_date: formValues.expiration_date,
    };
    return this.conventionRequestData;
  }

  private openConventionDialog() {
    const options = {
      data: {
        accessRequestData: this.buildConventionAccessRequestData(),
        customData: this.getDynamicFormValues(),
      },
      width: '800px',
      maxWidth: '95vw',
      height: 'auto',
      maxHeight: '90vh',
      hasBackdrop: true,
    };
    return this._dialog.open(ConventiondDialogContent, options);
  }

  private sendAccessRequest(payload: PermissionRequestPayload): void {
    const save$ = this.permissionRequest
      ? this._permissionRequestService.updatePermissionRequest(this.permissionRequest, payload)
      : this._permissionRequestService.createPermissionRequest(payload);

    save$
      .pipe(
        finalize(() => {
          this.isSaving = false;
        })
      )
      .subscribe({
        next: (result: PermissionRequest) => {
          this._router.navigate([
            `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.permissionRequest(result.id_permission_request)}`,
          ]);
        },
        error: (_error: any) => {
          // TODO: throw notifications
        },
      });
  }

  private _buildCustomAreaPayload() {
    if (!this.isCustomAreaMode) {
      return this.permissionRequest?.custom_area ? null : undefined;
    }
    if (!this.parsedGeoJson) return undefined;
    return { geojson: this.parsedGeoJson, file_name: this.selectedGeoJsonFileName };
  }

  // //////////////////////////////////////////////////////////////////////////
  // isSameAsPermissionRequest
  // //////////////////////////////////////////////////////////////////////////

  get isSameAsPermissionRequest(): boolean {
    if (!this.permissionRequest) return false;

    const rawValue = this.form.value as PermissionRequestFormValue;

    const normalizedDescription = (rawValue.description ?? '').trim();
    const permissionRequestDescription = (this.permissionRequest.description ?? '').trim();
    if (normalizedDescription !== permissionRequestDescription) return false;

    const normalizedExpiration = this._normalizeDateValue(rawValue.expiration_date);
    if (normalizedExpiration !== this._normalizeDateValue(this.permissionRequest.expiration_date))
      return false;

    if (!!rawValue.sensitivity_filter !== !!this.permissionRequest.sensitivity_filter) return false;

    if (
      (rawValue.scope ?? this.scopeFilterDefaultValue) !==
      (this.permissionRequest.scope ?? this.scopeFilterDefaultValue)
    )
      return false;

    const selectedTaxa = this._extractTaxaIdentifiers(rawValue.taxa).sort((a, b) => a - b);
    const savedTaxa = (this.permissionRequest.taxa ?? [])
      .map((t) => t.cd_nom)
      .sort((a, b) => a - b);
    if (
      selectedTaxa.length !== savedTaxa.length ||
      selectedTaxa.some((id, i) => id !== savedTaxa[i])
    )
      return false;

    const savedMode: AreaMode = this.permissionRequest.custom_area ? 'custom' : 'existing';
    if ((rawValue.area_mode ?? 'existing') !== savedMode) return false;

    if (rawValue.area_mode === 'custom') {
      if (this.parsedGeoJson) return false;
    } else {
      const selectedAreas = this._extractAreaIdentifiers(rawValue.areas).sort((a, b) => a - b);
      const savedAreas = (this.permissionRequest.areas ?? [])
        .map((a) => a.id_area)
        .sort((a, b) => a - b);
      if (
        selectedAreas.length !== savedAreas.length ||
        selectedAreas.some((id, i) => id !== savedAreas[i])
      )
        return false;
    }

    if (this.getDynamicFormValues() !== this.permissionRequest.additional_data) return false;

    return true;
  }

  onReset(): void {
    this._fillFormFromPermissionRequest();
    this._fillDynamicFormFromPermissionRequest();
  }

  // //////////////////////////////////////////////////////////////////////////
  // Helpers
  // //////////////////////////////////////////////////////////////////////////

  private _normalizeDateValue(value: NgbDateStruct | string | null | undefined): string | null {
    if (!value) return null;
    if (typeof value === 'string') return value || null;
    return this._dateParser.format(value) as unknown as string;
  }

  private _fillFormFromPermissionRequest(): void {
    this.parsedGeoJson = null;
    this.geoJsonParseError = null;
    this.selectedGeoJsonFileName = null;

    if (!this.permissionRequest) {
      this.form.reset({
        description: '',
        expiration_date: this.defaultEndExpirationDate,
        scope: this.scopeFilterDefaultValue,
        sensitivity_filter: this.sensitivityFilterDefaultValue,
        acknowledgeTerms: this.shouldDisplayAcknowledgement ? false : true,
        taxa: [],
        areas: [],
        area_mode: 'existing' as AreaMode,
      });
      this.selectedAreasDefaultItems = [];
    } else {
      const savedMode: AreaMode = this.permissionRequest.custom_area ? 'custom' : 'existing';
      this.form.patchValue({
        description: this.permissionRequest.description,
        expiration_date: this.permissionRequest.expiration_date
          ? this._dateParser.parse(this.permissionRequest.expiration_date)
          : null,
        scope: this.permissionRequest.scope ?? this.scopeFilterDefaultValue,
        sensitivity_filter: !!this.permissionRequest.sensitivity_filter,
        acknowledgeTerms: true,
        taxa: (this.permissionRequest.taxa ?? []).map((taxon) => ({
          cd_nom: taxon.cd_nom,
          lb_nom: taxon.lb_nom,
          nom_valide: taxon.nom_valide,
          displayName: taxon.nom_valide ?? taxon.lb_nom,
        })),
        areas: (this.permissionRequest.areas ?? []).map((area) => area.id_area),
        area_mode: savedMode,
      });
      this.selectedAreasDefaultItems = (this.permissionRequest.areas ?? []).map((area) => ({
        id_area: area.id_area,
        area_name: area.area_name,
        displayName: area.area_name,
      }));
    }
    this.form.markAsPristine();
    this.form.updateValueAndValidity({ emitEvent: false });
  }

  onDynamicFormInit(dynamicForm: FormGroup): void {
    this.dynamicFormGrp = dynamicForm;

    this._fillDynamicFormFromPermissionRequest();
  }

  private _fillDynamicFormFromPermissionRequest(): void {
    if (!this.permissionRequest) {
      this.dynamicFormGrp.reset({});
    } else {
      this.dynamicFormGrp.patchValue(this.permissionRequest.additional_data ?? {});
    }

    this.dynamicFormGrp.markAsPristine();
    this.dynamicFormGrp.updateValueAndValidity({ emitEvent: false });
  }

  // //////////////////////////////////////////////////////////////////////////
  // Form control accessors
  // //////////////////////////////////////////////////////////////////////////

  get expirationDateControl(): UntypedFormControl {
    return this.form.get('expiration_date') as UntypedFormControl;
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

  get taxaControl(): UntypedFormControl {
    return this.form.get('taxa') as UntypedFormControl;
  }

  get areasControl(): UntypedFormControl {
    return this.form.get('areas') as UntypedFormControl;
  }

  // //////////////////////////////////////////////////////////////////////////
  // Taxa / Area extraction
  // //////////////////////////////////////////////////////////////////////////

  private _extractTaxaIdentifiers(value: any): number[] {
    // WARNING: Extract only the cd_ref identifiers to assign permissions only to valid names!
    if (!Array.isArray(value)) return [];
    return value
      .map((item) => {
        if (!item) return null;
        if (typeof item === 'number') return item;
        if (typeof item === 'string' && item.trim()) return Number(item) || null;
        if (typeof item === 'object' && 'cd_ref' in item) return Number(item['cd_ref']);
        return null;
      })
      .filter((id): id is number => id !== null && Number.isFinite(id));
  }

  private _extractAreaIdentifiers(value: any): number[] {
    if (!Array.isArray(value)) return [];
    return value
      .map((item) => {
        if (item == null) return null;
        if (typeof item === 'number') return item;
        if (typeof item === 'string' && item.trim()) return Number(item) || null;
        if (typeof item === 'object' && 'id_area' in item) return Number(item['id_area']);
        return null;
      })
      .filter((id): id is number => id !== null && Number.isFinite(id));
  }

  onTaxaSelectionChange(allSelectedTaxa: any[]) {
    this.updateConventionTaxa(allSelectedTaxa);

    this.selectedTaxaDefaultItems = Array.isArray(allSelectedTaxa) ? allSelectedTaxa : [];

    this.taxaControl?.markAsDirty();
    this.taxaControl?.markAsTouched();
  }

  private updateConventionTaxa(allSelectedTaxa: any[]): void {
    if (this.shouldDisplayConvention) {
      this.conventionRequestData.taxa = [];
      allSelectedTaxa.forEach((item) => {
        this.conventionRequestData.taxa.push(item.displayName ?? '');
      });
    }
  }

  onAreasSelectionChange(allSelectedAreas: any[]): void {
    this.updateConventionAreas(allSelectedAreas);
    this.selectedAreasDefaultItems = Array.isArray(allSelectedAreas) ? allSelectedAreas : [];

    this.areasControl?.markAsDirty();
    this.areasControl?.markAsTouched();
  }

  private updateConventionAreas(allSelectedAreas: any[]): void {
    if (this.shouldDisplayConvention) {
      this.conventionRequestData.areas = [];
      allSelectedAreas.forEach((item) => {
        this.conventionRequestData.areas.push(item.area_name.trim() ?? '');
      });
    }
  }
}
