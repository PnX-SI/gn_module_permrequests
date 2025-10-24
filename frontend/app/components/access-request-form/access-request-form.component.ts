import { Component, EventEmitter, Input, OnChanges, Output, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { Router } from '@angular/router';

import { NgbDateParserFormatter, NgbDateStruct } from "@ng-bootstrap/ng-bootstrap";

import { finalize } from 'rxjs/operators';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
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
    private _moduleService: ModuleService,
    private _router: Router
  ) {}

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
      this.form.patchValue({
        description: this.accessRequest.description,
        expiration_date: this.accessRequest.expiration_date,
      });
    }
    this.form.markAsPristine();
  }
  get accessRequest(): AccessRequest | null {
    return this._accessRequest;
  }

  // //////////////////////////////////////////////////////////////////////////
  // Form
  // //////////////////////////////////////////////////////////////////////////

  form: FormGroup = this._buildForm();

  private _buildForm(): FormGroup {
    return this._formBuilder.group({
      description: [''],
      expiration_date: ['', [Validators.required]],
      id_validator: [null],
    });
  }

  onSubmit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const rawValue = this.form.value as {
      description: string;
      expiration_date: NgbDateStruct;
      id_validator: number | null;
    };

    console.log(this._dateParser.format(rawValue.expiration_date));

    const payload: AccessRequestPayload = {
      description: rawValue.description?.trim() || null,
      expiration_date: this._dateParser.format(rawValue.expiration_date) as unknown as string,
    };

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
      this._accessRequestService
        .createAccessRequest(payload)
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
}
