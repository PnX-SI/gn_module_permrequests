import { Component, EventEmitter, Input, OnChanges, Output, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { Router } from '@angular/router';

import { NgbDateParserFormatter, NgbDateStruct } from '@ng-bootstrap/ng-bootstrap';

import { finalize } from 'rxjs/operators';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { FormService } from '@geonature_common/form/form.service';
import { ModuleService } from '@geonature/services/module.service';

import { AccessRequest } from '../../models/accessRequest';
import { AccessRequestPayload, AccessRequestService } from '../../services/accessRequest.service';

@Component({
  standalone: true,
  selector: 'access-request-form',
  templateUrl: 'access-request-form.component.html',
  styleUrls: ['./access-request-form.component.scss'],
  imports: [GN2CommonModule, CommonModule, ReactiveFormsModule, MatButtonModule],
})
export class AccessRequestFormComponent {
  isSaving = false;

  constructor(
    private _accessRequestService: AccessRequestService,
    private _dateParser: NgbDateParserFormatter,
    private _formBuilder: FormBuilder,
    private _formService: FormService,
    private _moduleService: ModuleService,
    private _router: Router
  ) {
    this._setupValidators();
  }

  // //////////////////////////////////////////////////////////////////////////
  // AccessRequest
  // //////////////////////////////////////////////////////////////////////////

  _accessRequest: AccessRequest | null = null;

  @Input()
  set accessRequest(accessRequest: AccessRequest | null) {
    this._accessRequest = accessRequest;
    if (!this.accessRequest) {
      this.form.reset();
    } else {
      const initializationStruct = this.accessRequest.initialization_date
        ? this._dateParser.parse(this.accessRequest.initialization_date)
        : null;
      const expirationStruct = this.accessRequest.expiration_date
        ? this._dateParser.parse(this.accessRequest.expiration_date)
        : null;
      this.form.patchValue({
        description: this.accessRequest.description,
        initialization_date: initializationStruct,
        expiration_date: expirationStruct,
        id_validator: this.accessRequest.id_validator,
      });
    }
    this.form.markAsPristine();
    this.form.updateValueAndValidity({ emitEvent: false });
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

  onSubmit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const rawValue = this.form.value as {
      description: string;
      initialization_date: NgbDateStruct | string | null;
      expiration_date: NgbDateStruct;
      id_validator: number | null;
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
            this.accessRequest = updatedAccessRequest;
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
              `/${this._moduleService.currentModule.module_url}/${createdAccessRequest.id_access_request}`,
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

  get expirationDateControl() {
    return this.form.get('expiration_date');
  }

  get initializationDateControl() {
    return this.form.get('initialization_date');
  }
}
